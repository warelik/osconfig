#!/usr/bin/env python3
import ast
import base64
import hashlib
import inspect
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import maintenance
import release


class ExactShaReviewTests(unittest.TestCase):
    sha = "a" * 40
    requested = "2026-10-17T12:00:00Z"

    def clean_native_comment(self, commit=None):
        state = {
            "code_review": {
                "commit_sha": commit or self.sha,
                "status": "completed",
                "has_any_findings": False,
                "has_unresolved_findings": False,
            }
        }
        return {
            "user": {"login": release.BOT, "type": "Bot"},
            "performed_via_github_app": {"slug": release.APP},
            "created_at": "2026-10-17T12:10:00Z",
            "body": f"<!-- codex-review-state:v1 {json.dumps(state)} -->",
        }

    def gate(self, reviews=None, inline=None, comments=None):
        return release.review_gate(self.sha, self.requested, reviews or [],
                                   inline or [], comments or [], lambda prefix: self.sha)

    def test_clean_native_review_of_exact_sha_is_accepted(self):
        ready, reason = self.gate(comments=[self.clean_native_comment()])
        self.assertTrue(ready, reason)

    def test_native_review_of_an_older_sha_is_not_accepted(self):
        ready, reason = self.gate(comments=[self.clean_native_comment("b" * 40)])
        self.assertFalse(ready)
        self.assertEqual(reason, release.WAITING)


class ClosedPolicyBundleReuseTests(unittest.TestCase):
    repo = "warelik/osconfig"
    upstream = "1" * 40
    baseline = "2" * 40
    application = "3" * 40
    review_context = "4" * 40
    delta_sha = "5" * 40

    def setUp(self):
        self.candidate = {
            "schema": 1,
            "repository": self.repo,
            "upstream_sha": self.upstream,
            "application_sha": self.application,
            "configuration_sha": self.delta_sha,
            "patchset_sha256": "6" * 64,
            "recipe_sha256": "7" * 64,
            "platform": "fedora-44/x86_64",
        }
        self.candidate_id = release.frozen_candidate_identity(self.candidate)
        self.full_branch = f"review/{self.upstream}-{self.candidate_id}"
        self.delta_branch = f"review/changes-{self.delta_sha}"
        self.record = {
            "schema": 1,
            "proposalPr": 21,
            "proposalHead": "8" * 40,
            "candidate": self.candidate,
            "candidateId": self.candidate_id,
            "applicationSha": self.application,
            "reviewSourceSha": self.review_context,
            "baselineConfig": self.baseline,
            "deltaSha": self.delta_sha,
            "deltaPr": 22,
        }
        self.full = {
            "number": 21,
            "state": "closed",
            "base": {"ref": f"review-base/{self.upstream}", "sha": self.upstream,
                     "repo": {"full_name": self.repo}},
            "head": {"ref": self.full_branch, "sha": self.review_context,
                     "repo": {"full_name": self.repo}},
            "body": "<!-- osconfig-policy-candidate:v1 "
                    + json.dumps(self.record, sort_keys=True, separators=(",", ":"))
                    + " -->",
        }
        self.delta = {
            "number": 22,
            "state": "closed",
            "base": {"ref": f"review-base/{self.baseline}", "sha": self.baseline,
                     "repo": {"full_name": self.repo}},
            "head": {"ref": self.delta_branch, "sha": self.delta_sha,
                     "repo": {"full_name": self.repo}},
        }

    def recover(self, *, full=None, delta=None, receipt=True):
        with patch.object(release, "find_review_pull", return_value=full or self.full), \
             patch.object(release, "api", return_value=delta or self.delta) as github_api, \
             patch.object(release, "validated_policy_bundle", return_value=receipt) as bundle:
            result = release.closed_policy_bundle_reuse(
                self.repo, self.candidate, self.candidate_id, self.upstream,
                self.baseline, self.application, self.review_context)
        return result, github_api, bundle

    def test_prepare_reuse_probe_accepts_exact_closed_policy_pair_and_bundle(self):
        result, github_api, bundle = self.recover()
        self.assertEqual(result, (self.full, self.delta, self.full_branch))
        github_api.assert_called_once_with(f"repos/{self.repo}/pulls/22")
        bundle.assert_called_once_with(self.repo, self.candidate, 21)
        self.assertEqual(self.full["body"], "<!-- osconfig-policy-candidate:v1 "
                         + json.dumps(self.record, sort_keys=True, separators=(",", ":"))
                         + " -->")

    def test_prepare_reuse_probe_rejects_wrong_candidate_or_context(self):
        for field, value in (("candidateId", "9" * 64),
                             ("applicationSha", "a" * 40),
                             ("reviewSourceSha", "b" * 40),
                             ("baselineConfig", "c" * 40),
                             ("deltaSha", "d" * 40)):
            with self.subTest(field=field):
                record = dict(self.record, **{field: value})
                full = dict(self.full, body="<!-- osconfig-policy-candidate:v1 "
                            + json.dumps(record, sort_keys=True, separators=(",", ":"))
                            + " -->")
                with patch.object(release, "find_review_pull", return_value=full), \
                     patch.object(release, "api") as github_api, \
                     patch.object(release, "validated_policy_bundle") as bundle, \
                     self.assertRaisesRegex(ValueError, "exact candidate or context"):
                    release.closed_policy_bundle_reuse(
                        self.repo, self.candidate, self.candidate_id, self.upstream,
                        self.baseline, self.application, self.review_context)
                github_api.assert_not_called()
                bundle.assert_not_called()

    def test_prepare_reuse_probe_rejects_boolean_nested_candidate_schema(self):
        malformed_candidate = dict(self.candidate, schema=True)
        record = dict(self.record, candidate=malformed_candidate)
        full = dict(self.full, body="<!-- osconfig-policy-candidate:v1 "
                    + json.dumps(record, sort_keys=True, separators=(",", ":"))
                    + " -->")
        with patch.object(release, "find_review_pull", return_value=full), \
             patch.object(release, "api") as github_api, \
             patch.object(release, "validated_policy_bundle") as bundle, \
             self.assertRaisesRegex(ValueError, "marker candidate is malformed"):
            release.closed_policy_bundle_reuse(
                self.repo, self.candidate, self.candidate_id, self.upstream,
                self.baseline, self.application, self.review_context)
        github_api.assert_not_called()
        bundle.assert_not_called()

    def test_prepare_reuse_probe_rejects_wrong_delta_context_or_missing_bundle(self):
        wrong_delta = dict(self.delta)
        wrong_delta["head"] = dict(self.delta["head"], sha="e" * 40)
        with patch.object(release, "find_review_pull", return_value=self.full), \
             patch.object(release, "api", return_value=wrong_delta), \
             patch.object(release, "validated_policy_bundle") as bundle, \
             self.assertRaisesRegex(ValueError, "exact native delta PR context"):
            release.closed_policy_bundle_reuse(
                self.repo, self.candidate, self.candidate_id, self.upstream,
                self.baseline, self.application, self.review_context)
        bundle.assert_not_called()

        with self.assertRaisesRegex(ValueError, "verified exact shared bundle"):
            self.recover(receipt=False)

    def test_prepare_wires_exact_policy_reuse_before_branch_creation(self):
        source = inspect.getsource(release.prepare)
        self.assertIn("closed_policy_bundle_reuse(", source)
        self.assertIn("if pull is None:", source)
        self.assertIn("if not bundle_reuse:", source)

    def test_prepare_closed_bundle_delta_lookup_uses_native_branch_and_missing_refuses(self):
        source = inspect.getsource(release.prepare)
        tree = ast.parse(source)
        calls = [
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name)
                    and target.id == "recovered_delta_pull" for target in node.targets)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "find_review_pull"
        ]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(len(call.args), 3)
        self.assertTrue(all(isinstance(argument, ast.Name) for argument in call.args))
        fixture_values = {
            "repo": self.repo,
            "delta_base": self.baseline,
            "delta_base_branch": self.delta["base"]["ref"],
            "delta_branch": self.delta_branch,
        }
        lookup_args = [fixture_values[argument.id] for argument in call.args]
        state_keywords = [keyword.value for keyword in call.keywords
                          if keyword.arg == "states"]
        self.assertEqual(len(state_keywords), 1)
        states = ast.literal_eval(state_keywords[0])

        self.assertEqual(self.full["state"], "closed")
        self.assertEqual(self.delta["base"]["ref"], f"review-base/{self.baseline}")
        expected_head = f"{self.repo.split('/')[0]}:{self.delta_branch}"

        def read_native_pull(path):
            query = parse_qs(urlsplit(path).query)
            if (query.get("state") == ["closed"]
                    and query.get("base") == [self.delta["base"]["ref"]]
                    and query.get("head") == [expected_head]):
                return [self.delta]
            return []

        with patch.object(release, "pages", side_effect=read_native_pull):
            recovered = release.find_review_pull(*lookup_args, states=states)
        self.assertIs(recovered, self.delta)

        with patch.object(release, "pages", return_value=[]):
            missing = release.find_review_pull(*lookup_args, states=states)
        self.assertIsNone(missing)


class WorkflowActionPinTests(unittest.TestCase):
    def write_workflow(self, directory, content):
        path = Path(directory) / "workflow.yml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_alternate_full_sha_is_accepted_when_github_resolves_it(self):
        sha = "1" * 40
        other_sha = "2" * 40
        with tempfile.TemporaryDirectory() as temporary:
            workflow = self.write_workflow(
                temporary,
                f"name: test\njobs:\n  check:\n    steps:\n"
                f"      - uses: actions/checkout@{sha} # future reviewed pin\n"
                f"      - uses: actions/upload-artifact@{other_sha}\n",
            )
            with patch.object(
                release, "api", side_effect=lambda path: {"sha": path.rsplit("/", 1)[-1]},
            ) as github_api:
                self.assertEqual(release.verify_workflow_action_pins([workflow]),
                                 {("actions/checkout", sha), ("actions/upload-artifact", other_sha)})
        self.assertEqual(
            {call.args[0] for call in github_api.call_args_list},
            {f"repos/actions/checkout/commits/{sha}",
             f"repos/actions/upload-artifact/commits/{other_sha}"},
        )

    def test_missing_action_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            workflow = self.write_workflow(
                temporary,
                "name: no actions\njobs:\n  check:\n    steps:\n      - run: echo ready\n",
            )
            with patch.object(release, "api") as github_api, \
                 self.assertRaisesRegex(ValueError, "no semantic job or step uses"):
                release.verify_workflow_action_pins([workflow])
            github_api.assert_not_called()

    def test_key_like_text_inside_run_block_is_not_an_action_reference(self):
        sha = "5" * 40
        with tempfile.TemporaryDirectory() as temporary:
            workflow = self.write_workflow(
                temporary,
                "jobs:\n  check:\n    steps:\n      - run: |\n"
                "          uses: actions/moving@v4\n"
                f"      - uses: actions/checkout@{sha}\n",
            )
            with patch.object(release, "api", return_value={"sha": sha}) as github_api:
                self.assertEqual(release.verify_workflow_action_pins([workflow]),
                                 {("actions/checkout", sha)})
            github_api.assert_called_once_with(f"repos/actions/checkout/commits/{sha}")

    def test_folded_quoted_flow_and_aliased_remote_uses_are_rejected(self):
        sha = "6" * 40
        forms = {
            "folded scalar": "        - uses: >-\n            owner/moving@v4\n",
            "quoted key": '        - "uses": owner/moving@v4\n',
            "flow mapping": "        - {uses: owner/moving@v4}\n",
            "alias": ("        - &moving {uses: owner/moving@v4}\n"
                      "        - *moving\n"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            for label, extra in forms.items():
                with self.subTest(form=label):
                    workflow = self.write_workflow(
                        temporary,
                        "jobs:\n  check:\n    steps:\n"
                        f"        - uses: actions/checkout@{sha}\n{extra}",
                    )
                    with patch.object(release, "api") as github_api, \
                         self.assertRaisesRegex(ValueError, "full GitHub commit SHA"):
                        release.verify_workflow_action_pins([workflow])
                    github_api.assert_not_called()

    def test_reusable_workflow_ref_is_resolved_at_job_level(self):
        sha = "7" * 40
        with tempfile.TemporaryDirectory() as temporary:
            workflow = self.write_workflow(
                temporary,
                "jobs:\n  call-workflow:\n"
                f"    uses: owner/repository/.github/workflows/child.yml@{sha}\n",
            )
            with patch.object(release, "api", return_value={"sha": sha}) as github_api:
                self.assertEqual(release.verify_workflow_action_pins([workflow]),
                                 {("owner/repository", sha)})
        github_api.assert_called_once_with(f"repos/owner/repository/commits/{sha}")

    def test_malicious_python_yaml_tag_is_not_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "yaml-tag-executed"
            workflow = self.write_workflow(
                temporary,
                f'!!python/object/apply:os.system ["touch {marker}"]\n',
            )
            with patch.object(release, "api") as github_api, \
                 self.assertRaisesRegex(ValueError, "invalid or unsafe YAML"):
                release.verify_workflow_action_pins([workflow])
            github_api.assert_not_called()
            self.assertFalse(marker.exists())

    def test_malformed_or_moving_action_references_are_rejected(self):
        malformed = (
            "actions/checkout@v4",
            "actions/checkout@" + "A" * 40,
            "actions/checkout",
            "docker://example/action:latest",
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, reference in enumerate(malformed):
                with self.subTest(reference=reference):
                    workflow = self.write_workflow(
                        temporary,
                        f"name: test\njobs:\n  check:\n    steps:\n      - uses: {reference}\n",
                    )
                    with patch.object(release, "api") as github_api, \
                         self.assertRaisesRegex(ValueError, "full GitHub commit SHA"):
                        release.verify_workflow_action_pins([workflow])
                    github_api.assert_not_called()

    def test_unknown_pinned_commit_is_rejected(self):
        sha = "2" * 40
        with tempfile.TemporaryDirectory() as temporary:
            workflow = self.write_workflow(
                temporary,
                f"jobs:\n  check:\n    steps:\n      - uses: owner/action@{sha}\n",
            )
            failure = subprocess.CalledProcessError(1, ["gh", "api"])
            with patch.object(release, "api", side_effect=failure), \
                 self.assertRaisesRegex(ValueError, "could not resolve"):
                release.verify_workflow_action_pins([workflow])

    def test_github_response_must_match_the_requested_commit(self):
        sha = "3" * 40
        with tempfile.TemporaryDirectory() as temporary:
            workflow = self.write_workflow(
                temporary,
                f"jobs:\n  check:\n    steps:\n      - uses: owner/action@{sha}\n",
            )
            with patch.object(release, "api", return_value={"sha": "4" * 40}), \
                 self.assertRaisesRegex(ValueError, "different commit"):
                release.verify_workflow_action_pins([workflow])


class SigningWorkflowTrustTests(unittest.TestCase):
    def workflow_path(self):
        return Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_WORKFLOW") or
                    (release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"))

    def load_document(self, directory):
        yaml = release.yaml_module()
        original = self.workflow_path()
        document = yaml.safe_load(original.read_text(encoding="utf-8"))
        path = Path(directory) / "workflow.yml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return yaml, document, path

    def test_candidate_workflow_uses_trusted_checkout_signer_and_regression(self):
        release.validate_signing_workflow(self.workflow_path())

    def test_installed_and_template_workflows_use_the_trusted_receipt_command(self):
        installed = release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml"
        template = release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"
        self.assertEqual(installed.read_bytes(), template.read_bytes())
        for workflow in (installed, template):
            with self.subTest(workflow=workflow):
                release.validate_signing_workflow(workflow)
                document = release.yaml_module().safe_load(workflow.read_text(encoding="utf-8"))
                receipt = next(
                    step for step in document["jobs"]["sign"]["steps"]
                    if step.get("name") == "Verify and receipt the exact read-only lifecycle source"
                )
                self.assertEqual(
                    receipt["run"].strip(), release.TRUSTED_LIFECYCLE_RECEIPT_COMMAND,
                )

    def test_lifecycle_receipt_rejects_added_commands_and_secret_access(self):
        command = release.TRUSTED_LIFECYCLE_RECEIPT_COMMAND
        tampered_commands = {
            "appended shell command": command + "\necho untrusted",
            "prefixed shell command": "echo untrusted\n" + command,
            "signer overwrite": command + "\nprintf tampered > .vps/google-osconfig-agent/patches/sign-repo.sh",
            "regression overwrite": command + "\nprintf tampered > .vps/google-osconfig-agent/patches/tests/signing.sh",
            "signing secret reference": command + '\nprintf "%s" "${{ secrets.OSCONFIG_RPM_SIGNING_PRIVATE_KEY }}"',
        }
        for description, tampered in tampered_commands.items():
            with self.subTest(description=description), tempfile.TemporaryDirectory() as temporary:
                _, document, path = self.load_document(temporary)
                receipt = next(
                    step for step in document["jobs"]["sign"]["steps"]
                    if step.get("name") == "Verify and receipt the exact read-only lifecycle source"
                )
                receipt["run"] = command
                path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
                release.validate_signing_workflow(path)

                receipt["run"] = tampered
                path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "exact trusted lifecycle receipt command"):
                    release.validate_signing_workflow(path)

    def test_publish_and_adopt_verify_the_real_signed_artifact_layout(self):
        document = release.yaml_module().safe_load(self.workflow_path().read_text(encoding="utf-8"))
        for job_name, operation in (("publish", "verify"), ("adopt", "adopt")):
            with self.subTest(job=job_name):
                steps = document["jobs"][job_name]["steps"]
                downloads = {
                    (step.get("with", {}).get("name"), step.get("with", {}).get("path"))
                    for step in steps if str(step.get("uses", "")).startswith("actions/download-artifact@")
                }
                self.assertIn(
                    ("google-osconfig-agent-pages", "${{ runner.temp }}/osconfig-pages/rpm"),
                    downloads,
                )
                self.assertIn(
                    ("google-osconfig-agent-built-rpm", "${{ runner.temp }}/osconfig-built"),
                    downloads,
                )
                verifier = next(
                    step for step in steps if f"release.py {operation}" in step.get("run", "")
                )
                self.assertEqual(
                    {
                        key: verifier["env"][key]
                        for key in ("EXPECTED_CANDIDATE_SHA", "EXPECTED_UPSTREAM_SHA", "EXPECTED_PATCH_SHA")
                    },
                    {
                        "EXPECTED_CANDIDATE_SHA": "${{ needs.candidate-source.outputs.sha }}",
                        "EXPECTED_UPSTREAM_SHA": "${{ needs.candidate-source.outputs.upstream }}",
                        "EXPECTED_PATCH_SHA": "${{ needs.candidate-source.outputs.patch }}",
                    },
                )
                command = verifier["run"]
                self.assertIn("sudo apt-get install -y gnupg jq rpm", command)
                self.assertIn(
                    'bash .vps/google-osconfig-agent/patches/verify-repo.sh '
                    '"$RUNNER_TEMP/osconfig-built" "$RUNNER_TEMP/osconfig-pages"',
                    command,
                )
                self.assertIn(
                    f'python3 -B .vps/google-osconfig-agent/patches/release.py {operation} '
                    '"$RUNNER_TEMP/osconfig-candidate" "$RUNNER_TEMP/osconfig-pages/rpm"',
                    command,
                )
                normalized_command = command.replace("\\\n", " ")
                self.assertIn("release.py verify-final-run", normalized_command)

    def test_signing_job_can_update_runner_image_and_build_tool_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, document, path = self.load_document(temporary)
            job = document["jobs"]["sign"]
            job["runs-on"] = "ubuntu-26.04"
            job["timeout-minutes"] = 35
            job["container"] = "fedora:45"
            install = next(step for step in job["steps"]
                           if str(step.get("run", "")).startswith("dnf "))
            install["run"] += " package-tools-v2"
            path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
            release.validate_signing_workflow(path)

    def test_candidate_signer_script_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, document, path = self.load_document(temporary)
            signer = next(step for step in document["jobs"]["sign"]["steps"]
                          if "OSCONFIG_RPM_SIGNING_PRIVATE_KEY" in (step.get("env") or {}))
            signer["run"] = signer["run"].replace(
                f"{release.PREFIX}sign-repo.sh", "$RUNNER_TEMP/osconfig-candidate/sign-repo.sh",
            )
            path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "trusted tools"):
                release.validate_signing_workflow(path)

    def test_signer_rejects_execution_overrides(self):
        for key, value in (("shell", "bash -c 'echo override; bash {0}'"),
                           ("working-directory", "${{ runner.temp }}/osconfig-built")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                yaml, document, path = self.load_document(temporary)
                signer = next(step for step in document["jobs"]["sign"]["steps"]
                              if "OSCONFIG_RPM_SIGNING_PRIVATE_KEY" in (step.get("env") or {}))
                signer[key] = value
                path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
                with self.assertRaises(ValueError):
                    release.validate_signing_workflow(path)

    def test_signer_rejects_package_urls_and_repository_overrides(self):
        for extra in (" https://example.invalid/untrusted.rpm", " --repofrompath=extra,https://example.invalid/"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                yaml, document, path = self.load_document(temporary)
                install = next(step for step in document["jobs"]["sign"]["steps"]
                               if str(step.get("run", "")).startswith("dnf "))
                install["run"] += extra
                path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
                with self.assertRaises(ValueError):
                    release.validate_signing_workflow(path)

    def test_signer_rejects_review_gate_disjunction(self):
        with tempfile.TemporaryDirectory() as temporary:
            yaml, document, path = self.load_document(temporary)
            document["jobs"]["sign"]["if"] += " || true"
            path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                release.validate_signing_workflow(path)

    def test_signer_rejects_action_subdirectory_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            yaml, document, path = self.load_document(temporary)
            checkout = next(step for step in document["jobs"]["sign"]["steps"]
                            if str(step.get("uses", "")).startswith("actions/checkout@")
                            and (step.get("with") or {}).get("ref") == "${{ github.sha }}")
            checkout["uses"] = checkout["uses"].replace("actions/checkout@", "actions/checkout/other@")
            path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                release.validate_signing_workflow(path)

    def test_signing_checkout_must_pin_the_exact_workflow_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, document, path = self.load_document(temporary)
            checkout = next(step for step in document["jobs"]["sign"]["steps"]
                            if str(step.get("uses", "")).startswith("actions/checkout@"))
            checkout["with"]["ref"] = "master"
            path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact trusted workflow commit"):
                release.validate_signing_workflow(path)

    def test_production_key_cannot_move_to_another_step(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, document, path = self.load_document(temporary)
            steps = document["jobs"]["sign"]["steps"]
            signer = next(step for step in steps
                          if "OSCONFIG_RPM_SIGNING_PRIVATE_KEY" in (step.get("env") or {}))
            secret = signer["env"].pop("OSCONFIG_RPM_SIGNING_PRIVATE_KEY")
            steps[0].setdefault("env", {})["OSCONFIG_RPM_SIGNING_PRIVATE_KEY"] = secret
            path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Only the trusted signer step"):
                release.validate_signing_workflow(path)

    def test_signing_workflow_rejects_job_wide_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, document, path = self.load_document(temporary)
            document["jobs"]["sign"]["env"] = {"PATH": "$RUNNER_TEMP/candidate-bin"}
            path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot supply job-wide secrets"):
                release.validate_signing_workflow(path)

    def test_signing_regression_must_precede_key_exposure(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, document, path = self.load_document(temporary)
            steps = document["jobs"]["sign"]["steps"]
            test_index = next(index for index, step in enumerate(steps)
                              if "tests/signing.sh" in step.get("run", ""))
            signer_index = next(index for index, step in enumerate(steps)
                                if "OSCONFIG_RPM_SIGNING_PRIVATE_KEY" in (step.get("env") or {}))
            steps[test_index], steps[signer_index] = steps[signer_index], steps[test_index]
            path.write_text(release.yaml_module().safe_dump(document, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "before the production key"):
                release.validate_signing_workflow(path)

    def test_review_command_failure_routes_to_publisher_repair(self):
        document = release.yaml_module().safe_load(self.workflow_path().read_text(encoding="utf-8"))
        repair = document["jobs"]["repair-publisher"]
        self.assertIn("review", repair["needs"])
        self.assertIn("final-guard", repair["needs"])
        self.assertIn("sign", repair["needs"])
        self.assertIn("recover-validated", repair["needs"])
        self.assertIn("needs.review.result == 'failure'", repair["if"])
        self.assertIn("needs.final-guard.result == 'failure'", repair["if"])
        self.assertIn("needs.sign.result == 'failure'", repair["if"])
        self.assertIn("needs.recover-validated.result == 'failure'", repair["if"])
        self.assertIn("release.py repair-policy", repair["steps"][-1].get("run", ""))

    def test_application_repair_waits_for_both_exact_review_scopes(self):
        document = release.yaml_module().safe_load(self.workflow_path().read_text(encoding="utf-8"))
        repair_if = document["jobs"]["repair"]["if"]
        self.assertIn("needs.review.outputs.reason != 'Waiting for Codex; no completed exact-SHA review'",
                      repair_if)
        self.assertIn(
            "needs.review.outputs.reason != 'Both distinct exact-source review lists must complete before repair'",
            repair_if)
        self.assertIn("needs.review.outputs.ready == 'false'", repair_if)


class ApplicationSourceIdentityTests(unittest.TestCase):
    def test_clean_existing_candidate_reuses_its_exact_application_sha(self):
        existing_sha = "a" * 40
        with patch.object(release, "run") as git:
            result = release.resolve_application_sha(
                None, pull={"number": 17}, repair_changed=False,
                existing_state={"candidate": {"application_sha": existing_sha}},
                repo_work=Path("/candidate/git"))
        self.assertEqual(result, existing_sha)
        git.assert_not_called()

    def test_changed_candidate_uses_its_assembled_head_sha(self):
        assembled_sha = "b" * 40
        with patch.object(release, "run", return_value=assembled_sha) as git:
            result = release.resolve_application_sha(
                None, pull={"number": 17}, repair_changed=True,
                existing_state={"candidate": {"application_sha": "a" * 40}},
                repo_work=Path("/candidate/git"))
        self.assertEqual(result, assembled_sha)
        git.assert_called_once_with("git", "rev-parse", "HEAD", cwd=Path("/candidate/git"))


class ParserRequirementTests(unittest.TestCase):
    def test_parser_requirement_accepts_an_exact_future_pyyaml_version(self):
        for version in ("6.0.3", "999999.0.0", "7.0rc1+policy.2"):
            with self.subTest(version=version):
                self.assertEqual(
                    release.parser_requirement_version(
                        f"# trusted comment\nPyYAML=={version} --hash=sha256:{'a' * 64}\n"
                    ),
                    version,
                )

    def test_parser_requirement_rejects_malformed_or_unverifiable_inputs(self):
        invalid = (
            "not a valid requirement\n",
            "--index-url https://example.invalid/simple\nPyYAML==6.0.3\n",
            "PyYAML @ https://example.invalid/PyYAML.whl\n",
            "PyYAML>=6\n",
            "PyYAML==6.0.3; python_version>='3.12'\n",
            "PyYAML==6.0.3\nOtherDependency==1\n",
            "PyYAML==6.*\n",
            f"PyYAML==6.0.3 --hash=sha256:{'a' * 63}\n",
            f"PyYAML==6.0.3 --hash=sha256:{'a' * 64} --hash=sha256:{'b' * 64}\n",
        )
        for content in invalid:
            with self.subTest(content=content), self.assertRaisesRegex(
                ValueError, "Publisher parser requirements",
            ):
                release.parser_requirement_version(content)


class PolicyWorkflowAndSharedValidationTests(unittest.TestCase):
    repo = "warelik/osconfig"

    def test_signing_validator_accepts_normalized_key_and_rejects_old_spelling(self):
        installed = release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml"
        template = release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"
        self.assertEqual(installed.read_bytes(), template.read_bytes())
        release._validate_shared_signing_workflow(installed)

        old_spelling = template.read_text(encoding="utf-8").replace(
            r"core\.sshcommand", r"core\.sshCommand")
        self.assertNotEqual(old_spelling, template.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(prefix="osconfig-signing-workflow-key-") as temporary:
            candidate = Path(temporary) / "workflow.yml"
            candidate.write_text(old_spelling, encoding="utf-8")
            with self.assertRaises(ValueError):
                release._validate_shared_signing_workflow(candidate)

    def test_owner_metadata_callers_get_the_owner_token_only_at_trusted_steps(self):
        workflow = Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_WORKFLOW") or
                        (release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"))
        document = release.yaml_module().safe_load(workflow.read_text(encoding="utf-8"))
        jobs = document["jobs"]
        trusted_calls = (
            ("adopt-policy", "Adopt only exact reviewed policy blobs without starting a second cycle"),
            ("recover-validated", "Verify exact prior run-attempt artifacts and signed metadata"),
            ("publish", "Recheck exact review and signed repository before publication"),
        )
        for job_name, step_name in trusted_calls:
            with self.subTest(job=job_name, step=step_name):
                matches = [step for step in jobs[job_name]["steps"]
                           if step.get("name") == step_name]
                self.assertEqual(len(matches), 1)
                env = matches[0].get("env", {})
                self.assertEqual(env.get("GH_TOKEN"), "${{ github.token }}")
                self.assertEqual(env.get("CODEX_REQUEST_TOKEN"),
                                 "${{ secrets.CODEX_REQUEST_TOKEN }}")

        self.assertNotIn("CODEX_REQUEST_TOKEN", document.get("env", {}))
        proposal_tests = next(
            step for step in jobs["prepare"]["steps"]
            if step.get("name") == "Sandbox and test the proposed publisher policy after both reviews")
        self.assertNotIn("CODEX_REQUEST_TOKEN", proposal_tests.get("env", {}))
        for job_name in ("build-rpm", "sign"):
            for step in jobs[job_name]["steps"]:
                with self.subTest(job=job_name, step=step.get("name")):
                    self.assertNotIn("CODEX_REQUEST_TOKEN", step.get("env", {}))

    def test_policy_proposal_repair_requires_an_exact_active_proposal(self):
        installed = release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml"
        template = release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"
        self.assertEqual(installed.read_bytes(), template.read_bytes())
        document = release.yaml_module().safe_load(installed.read_text(encoding="utf-8"))
        jobs = document["jobs"]
        policy_check = jobs["policy-check"]
        self.assertEqual(policy_check["outputs"]["pr"], "${{ steps.identity.outputs.pr }}")
        self.assertEqual(policy_check["outputs"]["head"], "${{ steps.identity.outputs.head }}")

        proposal_repair_if = " ".join(jobs["repair-policy-proposal"]["if"].split())
        self.assertIn("needs.policy-check.outputs.pr != ''", proposal_repair_if)
        self.assertIn("needs.policy-check.outputs.head != ''", proposal_repair_if)
        self.assertIn("needs.policy-check.result == 'failure'", proposal_repair_if)
        self.assertIn("needs.policy-check.outputs.changed == 'true'", proposal_repair_if)

        publisher_repair_if = " ".join(jobs["repair-publisher"]["if"].split())
        self.assertIn("needs.prepare.result == 'failure'", publisher_repair_if)
        self.assertIn("needs.build-rpm.outputs.failure_class == 'publisher'", publisher_repair_if)

        policy_guard = jobs["policy-final-guard"]["outputs"]
        self.assertEqual(policy_guard["policy_validation_reuse"],
                         "${{ steps.authorize.outputs.policy_validation_reuse }}")
        prepare = jobs["prepare"]
        self.assertIn("policy-proposal-history-reuse.outputs.policy_validated",
                      prepare["outputs"]["policy_validated"])
        proposal_step = next(step for step in prepare["steps"]
                             if step.get("id") == "policy-proposal")
        proposal_reuse = next(step for step in prepare["steps"]
                              if step.get("id") == "policy-proposal-history-reuse")
        self.assertIn("policy_validation_reuse != 'true'", proposal_step["if"])
        self.assertIn("policy_validation_reuse == 'true'", proposal_reuse["if"])

    def test_reviewed_policy_validation_uses_the_exact_proposal_private_pin(self):
        installed = release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml"
        template = release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"
        self.assertEqual(installed.read_bytes(), template.read_bytes())
        document = release.yaml_module().safe_load(installed.read_text(encoding="utf-8"))
        prepare = document["jobs"]["prepare"]
        self.assertIn("policy-review", prepare["needs"])
        self.assertIn("policy-final-guard", prepare["needs"])
        prepare_if = " ".join(prepare["if"].split())
        self.assertIn("needs.policy-review.result == 'success'", prepare_if)
        self.assertIn("needs.policy-review.outputs.ready == 'true'", prepare_if)
        self.assertIn("needs.policy-final-guard.result == 'success'", prepare_if)

        steps = prepare["steps"]
        proposal_test = next(step for step in steps if step.get("id") == "policy-proposal")
        proposal_if = " ".join(proposal_test["if"].split())
        pin = next(step for step in steps
                   if step.get("id") == "proposal-maintenance-pin")
        private_checkout = next(step for step in steps
                                if step.get("with", {}).get("path") == "machine-maintenance-proposal")
        receipt = next(step for step in steps
                       if step.get("name") == "Verify and receipt the reviewed proposal lifecycle source")
        for step in (pin, private_checkout, receipt):
            self.assertEqual(" ".join(step["if"].split()), proposal_if)

        pin_source = pin.get("run", "")
        self.assertIn('proposal_root = pathlib.Path("policy-candidate")', pin_source)
        self.assertIn(
            'relative_lock = pathlib.Path(".vps/google-osconfig-agent/patches/maintenance.lock.json")',
            pin_source)
        self.assertIn("object_pairs_hook=unique_object", pin.get("run", ""))
        self.assertIn("for part in relative_lock.parts", pin.get("run", ""))
        self.assertIn(
            "path.resolve(strict=True).is_relative_to(proposal_root.resolve())",
            pin.get("run", ""))
        self.assertIn("module_sha256", pin.get("run", ""))
        self.assertNotIn("trusted/.vps/google-osconfig-agent/patches/maintenance.lock.json",
                         pin.get("run", ""))
        self.assertEqual(private_checkout.get("with", {}).get("repository"),
                         "warelik/machine-maintenance")
        self.assertEqual(private_checkout.get("with", {}).get("ref"),
                         "${{ steps.proposal-maintenance-pin.outputs.revision }}")
        self.assertEqual(private_checkout.get("with", {}).get("persist-credentials"), False)
        self.assertIn("ssh-key", private_checkout.get("with", {}))
        self.assertEqual(receipt.get("env", {}).get("FORK_MAINTENANCE_ROOT"),
                         "${{ github.workspace }}/machine-maintenance-proposal")
        self.assertIn('git -C "$FORK_MAINTENANCE_ROOT" rev-parse HEAD', receipt.get("run", ""))
        self.assertIn(
            'git -C "$FORK_MAINTENANCE_ROOT" config --local --get-regexp',
            receipt.get("run", ""))
        self.assertIn("hashlib.sha256(source).hexdigest()", receipt.get("run", ""))

        trusted_test = next(step for step in steps
                            if step.get("name") == "Test trusted release gate after both reviews")
        self.assertEqual(trusted_test.get("env", {}).get("FORK_MAINTENANCE_ROOT"),
                         "${{ github.workspace }}/machine-maintenance")
        self.assertEqual(proposal_test.get("env", {}).get("FORK_MAINTENANCE_ROOT"),
                         "${{ github.workspace }}/machine-maintenance-proposal")

        positions = [steps.index(step) for step in (pin, private_checkout, receipt, proposal_test)]
        self.assertEqual(positions, sorted(positions))

    def test_workflow_copies_have_unique_yaml_keys_and_exact_resume_permissions(self):
        yaml = release.yaml_module()

        class UniqueKeyLoader(yaml.SafeLoader):
            pass

        def unique_mapping(loader, node, deep=False):
            values = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if key in values:
                    raise ValueError(f"duplicate YAML key {key!r}")
                values[key] = loader.construct_object(value_node, deep=deep)
            return values

        UniqueKeyLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
        installed = Path(__file__).resolve().parents[4] / ".github/workflows/google-osconfig-agent-inventory.yml"
        template = release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"
        self.assertEqual(installed.read_bytes(), template.read_bytes())
        documents = [yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
                     for path in (installed, template)]
        expected = {"contents": "read", "issues": "write", "actions": "write",
                    "pull-requests": "read"}
        self.assertEqual(documents[0]["jobs"]["policy-resume"]["permissions"], expected)
        self.assertEqual(documents[1]["jobs"]["policy-resume"]["permissions"], expected)


    def test_only_new_or_byte_changed_proposal_tests_are_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_tests = root / "candidate" / "tests"
            trusted_tests = root / "trusted" / "tests"
            candidate_tests.mkdir(parents=True)
            trusted_tests.mkdir(parents=True)
            (trusted_tests / "test_same.py").write_text("assert True\n", encoding="utf-8")
            (candidate_tests / "test_same.py").write_text("assert True\n", encoding="utf-8")
            (trusted_tests / "test_changed.py").write_text("assert True\n", encoding="utf-8")
            (candidate_tests / "test_changed.py").write_text("assert False\n", encoding="utf-8")
            (candidate_tests / "test_new.py").write_text("assert True\n", encoding="utf-8")

            self.assertEqual(
                [path.name for path in release.candidate_policy_tests(candidate_tests, trusted_tests)],
                ["test_changed.py", "test_new.py"],
            )

    def test_accepted_config_comparison_reads_product_and_policy_roots_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product_root = root / "product"
            policy_root = root / "policy"
            product_file = product_root / release.PREFIX / "build-rpm.sh"
            policy_file = policy_root / release.PREFIX / "release.py"
            diagnostic_file = policy_root / release.PREFIX / "check-upstream.sh"
            product_file.parent.mkdir(parents=True)
            policy_file.parent.mkdir(parents=True)
            diagnostic_file.parent.mkdir(parents=True, exist_ok=True)
            product_file.write_text("product recipe\n", encoding="utf-8")
            policy_file.write_text("trusted controller\n", encoding="utf-8")
            diagnostic_file.write_text("trusted local diagnostic\n", encoding="utf-8")
            hashes = {str(product_file): "a" * 40, str(policy_file): "b" * 40,
                      str(diagnostic_file): "c" * 40}
            tree = {"truncated": False, "tree": [
                {"path": release.PREFIX + "build-rpm.sh", "mode": "100644", "sha": "a" * 40,
                 "type": "blob"},
                {"path": release.PREFIX + "release.py", "mode": "100644", "sha": "b" * 40,
                 "type": "blob"},
                {"path": release.PREFIX + "check-upstream.sh", "mode": "100644", "sha": "c" * 40,
                 "type": "blob"},
            ]}
            with patch.object(release, "api", return_value=tree), \
                    patch.object(release, "run", side_effect=lambda *args, **kwargs: hashes[str(args[-1])]):
                self.assertTrue(release.candidate_config_inputs_match(
                    self.repo, "c" * 40, product_root, policy_root))

    def test_candidate_module_is_imported_before_immutable_test_discovery(self):
        launcher = release.POLICY_TEST_LAUNCHER
        self.assertLess(launcher.index("import release;"), launcher.index("release.lifecycle_module();"))
        self.assertLess(launcher.index("release.lifecycle_module();"),
                        launcher.index("discover(discover_tests"))
        with tempfile.TemporaryDirectory() as temporary:
            changed = Path(temporary) / "test_changed.py"
            new = Path(temporary) / "test_new.py"
            targets = release.shared_policy_test_targets(
                Path("candidate/patches"), Path("trusted/tests"),
                Path("candidate/tests"), [changed, new],
            )
            self.assertEqual(len(targets), 2)
            self.assertEqual(targets[0][1], release.POLICY_TEST_LAUNCHER)
            self.assertEqual(targets[0][3:], (Path("trusted/tests"), ("trusted/tests",)))
            self.assertEqual(targets[1][1], release.PROPOSED_POLICY_TEST_LAUNCHER)
            self.assertEqual(targets[1][3:], (Path("candidate/tests"), ("test_changed", "test_new")))
            self.assertLess(targets[1][1].index("import release;"),
                            targets[1][1].index("release.lifecycle_module();"))
            self.assertLess(targets[1][1].index("release.lifecycle_module();"),
                            targets[1][1].index("loadTestsFromName(name)"))

    def test_bundle_reuse_uses_owner_authenticated_read_only_native_callback(self):
        repo = "warelik/osconfig"
        candidate = {
            "schema": 1, "repository": repo,
            "upstream_sha": "a" * 40, "application_sha": "b" * 40,
            "configuration_sha": "c" * 40, "patchset_sha256": "d" * 64,
            "recipe_sha256": "e" * 64, "platform": "fedora-44/x86_64",
        }
        comments = [{"id": 91, "body": "exact full review thread"}]
        native_response = {"id": 701}

        class Core:
            @staticmethod
            def validated_bundle(value, native_comments, read_native):
                self.assertEqual(value, candidate)
                self.assertEqual(native_comments, comments)
                self.assertEqual(read_native("repos/warelik/machine-maintenance/actions/runs/1"),
                                 native_response)
                return {"decision": "reuse-policy-validation"}

        with patch.object(release, "owner_token", return_value="owner-read-token"), \
             patch.object(release, "pages", return_value=comments) as native_comments, \
             patch.object(release, "api", return_value=native_response) as native_get, \
             patch.object(maintenance, "validated_bundle", side_effect=Core.validated_bundle):
            self.assertTrue(release.validated_policy_bundle(repo, candidate, 91))
        native_comments.assert_called_once_with(
            "repos/warelik/osconfig/issues/91/comments", token="owner-read-token")
        native_get.assert_called_once_with(
            "repos/warelik/machine-maintenance/actions/runs/1", token="owner-read-token")

    def test_expensive_steps_recheck_the_frozen_native_run_attempt(self):
        workflow = Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_WORKFLOW") or
                        (release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"))
        document = release.yaml_module().safe_load(workflow.read_text(encoding="utf-8"))
        jobs = document["jobs"]
        self.assertIn("run_attempt", jobs["final-guard"]["outputs"])
        self.assertIn("run_id", jobs["final-guard"]["outputs"])
        self.assertIn("workflow_sha", jobs["final-guard"]["outputs"])
        build_steps = jobs["build-rpm"]["steps"]
        final_guard = next(index for index, step in enumerate(build_steps)
                           if "release.py verify-final-run" in step.get("run", ""))
        build = next(index for index, step in enumerate(build_steps)
                     if step.get("name") == "Build the Fedora RPM")
        self.assertLess(final_guard, build)
        build_initial = build_steps[0]
        self.assertIn("before checkout or Fedora tools", build_initial.get("name", ""))
        self.assertIn("GITHUB_RUN_ATTEMPT", build_initial.get("run", ""))
        self.assertLess(build_steps.index(build_initial), next(
            index for index, step in enumerate(build_steps)
            if step.get("name") == "Install Fedora build tools"))
        self.assertIn("github.run_attempt", jobs["sign"]["if"])
        sign_steps = jobs["sign"]["steps"]
        self.assertIn("before checkout or signing tools", sign_steps[0].get("name", ""))
        self.assertIn("GITHUB_RUN_ATTEMPT", sign_steps[0].get("run", ""))
        recovery = jobs["recover-validated"]
        self.assertIn("already-validated", recovery["if"])
        recovery_downloads = [step.get("with", {}) for step in recovery["steps"]
                             if str(step.get("uses", "")).startswith("actions/download-artifact@")]
        self.assertTrue(any(item.get("run-id") == "${{ needs.final-guard.outputs.reuse_run_id }}"
                            for item in recovery_downloads))
        self.assertTrue(any("verify-reusable-artifacts" in step.get("run", "")
                            for step in recovery["steps"]))
        self.assertIn("always()", jobs["publish"]["if"])
        self.assertEqual(release.FINAL_REQUIRED_JOBS, ("build-rpm", "sign"))
        policy_test = next(step for step in jobs["prepare"]["steps"]
                           if step.get("name") == "Test trusted release gate after both reviews")
        self.assertIn("release.py policy-tests", policy_test.get("run", ""))
        self.assertNotIn("unittest discover", policy_test.get("run", ""))

    def test_build_rpm_removes_private_checkout_before_candidate_code(self):
        workflow = Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_WORKFLOW") or
                        (release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"))
        document = release.yaml_module().safe_load(workflow.read_text(encoding="utf-8"))
        jobs = document["jobs"]
        build_steps = jobs["build-rpm"]["steps"]
        verify_index = next(index for index, step in enumerate(build_steps)
                            if "release.py verify-final-run" in step.get("run", ""))
        remove_index = next(index for index, step in enumerate(build_steps)
                            if step.get("name") ==
                            "Remove private lifecycle checkout before candidate build code")
        builder_index = next(index for index, step in enumerate(build_steps)
                             if step.get("name") == "Build the Fedora RPM")
        provenance_index = next(index for index, step in enumerate(build_steps)
                                if "release.py write-build-provenance" in " ".join(
                                    step.get("run", "").replace("\\\n", " ").split()))
        self.assertLess(verify_index, remove_index)
        self.assertLess(remove_index, builder_index)
        self.assertLess(builder_index, provenance_index)
        removal = build_steps[remove_index]
        self.assertEqual(removal.get("shell"), "bash")
        self.assertEqual(removal.get("run", "").strip(), '''set -euo pipefail
[[ -n "$GITHUB_WORKSPACE" && "$GITHUB_WORKSPACE" != "/" ]]
private_root="$GITHUB_WORKSPACE/machine-maintenance"
rm -rf -- "$private_root"
[[ ! -e "$private_root" && ! -L "$private_root" ]]''')
        for index in (remove_index, builder_index, provenance_index):
            self.assertNotIn("FORK_MAINTENANCE_ROOT", build_steps[index].get("env", {}))
        self.assertIn("EXPECTED_CANDIDATE_ID", build_steps[provenance_index].get("env", {}))

        candidate_upload = next(
            step for step in jobs["candidate-source"]["steps"]
            if step.get("with", {}).get("name") == "google-osconfig-agent-candidate")
        self.assertEqual(candidate_upload["with"].get("path"),
                         "${{ runner.temp }}/osconfig-candidate/inputs")
        sign_verify = next(
            step for step in jobs["sign"]["steps"]
            if step.get("name") == "Verify this exact native run and built RPM receipt")
        self.assertIn("FORK_MAINTENANCE_ROOT", sign_verify.get("env", {}))
        self.assertIn("release.py verify-final-run", sign_verify.get("run", ""))
        self.assertIn("release.py verify-build-provenance", sign_verify.get("run", ""))
        signature_proof = next(
            step for step in jobs["sign"]["steps"]
            if step.get("name") == "Record the exact native signature artifact identity")
        self.assertIn("FORK_MAINTENANCE_ROOT", signature_proof.get("env", {}))
        signature_command = " ".join(
            signature_proof.get("run", "").replace("\\\n", " ").split())
        self.assertIn("release.py write-signature-proof", signature_command)

    def test_final_history_ignores_only_timestamped_native_skipped_placeholders(self):
        self.assertFalse(release.native_heavy_job_started({
            "started_at": "2026-10-19T00:00:00Z", "conclusion": "skipped", "steps": [],
        }))
        self.assertFalse(release.native_heavy_job_started({
            "started_at": None, "conclusion": "skipped", "steps": [],
        }))
        self.assertTrue(release.native_heavy_job_started({
            "started_at": "2026-10-19T00:00:00Z", "conclusion": "skipped",
            "steps": [{"name": "real work", "conclusion": "skipped"}],
        }))


class PolicyBootstrapWorkflowTests(unittest.TestCase):
    def test_policy_check_bootstrap_does_not_read_mutable_candidate_requirements(self):
        workflow = Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_WORKFLOW") or
                        (release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml"))
        document = release.yaml_module().safe_load(workflow.read_text(encoding="utf-8"))
        prepare_steps = document["jobs"]["prepare"]["steps"]
        declared_install = [step for step in prepare_steps
                            if step.get("name") == "Install declared workflow parser dependency"]
        self.assertEqual(len(declared_install), 1)
        self.assertIn("--require-hashes", declared_install[0]["run"])
        self.assertIn("-r .vps/google-osconfig-agent/patches/requirements-policy.txt",
                      declared_install[0]["run"])
        steps = document["jobs"]["policy-check"]["steps"]
        self.assertFalse(any("pip install" in step.get("run", "")
                             or "release.py policy-check candidate" in step.get("run", "")
                             for step in steps))
        review_steps = document["jobs"]["policy-review"]["steps"]
        paired_review = [step for step in review_steps
                         if "release.py review-pair" in step.get("run", "")]
        self.assertEqual(len(paired_review), 1)
        self.assertIn("policy-final-guard", document["jobs"]["prepare"]["needs"])
        self.assertIn("policy-review", document["jobs"]["prepare"]["needs"])
        final_authorize = next(step for step in document["jobs"]["final-guard"]["steps"]
                               if step.get("id") == "authorize")
        self.assertIn("CODEX_REQUEST_TOKEN", final_authorize.get("env", {}))
        policy_authorize = next(step for step in document["jobs"]["policy-final-guard"]["steps"]
                                if step.get("id") == "authorize")
        self.assertIn("CODEX_REQUEST_TOKEN", policy_authorize.get("env", {}))
        build_verify = next(step for step in document["jobs"]["build-rpm"]["steps"]
                            if "release.py verify-final-run" in step.get("run", ""))
        self.assertNotIn("CODEX_REQUEST_TOKEN", build_verify.get("env", {}))
        self.assertIn("validated_bundle", document["jobs"]["final-guard"]["outputs"])
        self.assertIn("validated_bundle", document["jobs"]["policy-final-guard"]["outputs"])
        self.assertEqual(document["jobs"]["policy-check"]["outputs"]["candidate_id"],
                         "${{ steps.check.outputs.candidate_id }}")
        preflight = next(step for step in document["jobs"]["candidate-source"]["steps"]
                         if step.get("id") == "preflight")
        self.assertIn("release.py candidate-preflight", preflight.get("run", ""))
        check = [step for step in steps if "release.py prepare-policy candidate" in step.get("run", "")]
        self.assertEqual(len(check), 1)
        self.assertIn("CODEX_REQUEST_TOKEN", check[0].get("env", {}))
        proposal = [step for step in prepare_steps
                    if step.get("name") == "Sandbox and test the proposed publisher policy after both reviews"]
        self.assertEqual(len(proposal), 1)
        self.assertIn("policy-validate-shared", proposal[0].get("run", ""))
        self.assertIn("validated_bundle != 'true'", proposal[0].get("if", ""))
        reuse = [step for step in prepare_steps
                 if step.get("id") == "policy-proposal-reuse"]
        self.assertEqual(len(reuse), 1)
        self.assertIn("validated_bundle == 'true'", reuse[0].get("if", ""))
        self.assertIn("policy-proposal-reuse.outputs.policy_validated",
                      document["jobs"]["prepare"]["outputs"]["policy_validated"])

class PairedPolicyAdoptionCredentialTests(unittest.TestCase):
    repo = "warelik/osconfig"

    def invoke_adoption(self, changed, *, missing_owner_token=False):
        baseline, proposal_head = "1" * 40, "2" * 40
        reviewed_sha, application_sha, adopted_sha = "3" * 40, "4" * 40, "5" * 40
        delta_branch = f"review/changes-{reviewed_sha}"
        branch = "repair/osconfig-policy-70"
        candidate = {
            "schema": 1, "repository": self.repo,
            "upstream_sha": "6" * 40, "application_sha": application_sha,
            "configuration_sha": reviewed_sha,
            "patchset_sha256": "7" * 64, "recipe_sha256": "8" * 64,
            "platform": "fedora-44/x86_64",
        }
        contexts = {
            "full": {"pr": 71, "review_sha": "9" * 40, "base_sha": "a" * 40,
                     "head_branch": "review/full", "base_branch": "review-base/full"},
            "delta": {"pr": 72, "review_sha": reviewed_sha, "base_sha": baseline,
                      "head_branch": delta_branch, "base_branch": f"review-base/{baseline}"},
        }
        manifest = {
            "candidate": candidate, "configSha": baseline,
            "proposalHeadSha": proposal_head, "proposalPr": 70,
            "candidatePr": 71, "deltaPr": 72, "reviewContexts": contexts,
        }
        proposal = {
            "number": 70, "state": "open", "user": {"login": "warelik", "type": "User"},
            "head": {"sha": proposal_head, "ref": branch,
                     "repo": {"full_name": self.repo}},
            "base": {"sha": baseline, "ref": "master",
                     "repo": {"full_name": self.repo}},
        }
        push_calls, api_calls = [], []
        token_error = ValueError("fixture owner token unavailable")

        def api(path, *, method="GET", data=None, **_kwargs):
            api_calls.append((path, method))
            if path == f"repos/{self.repo}/pulls/70":
                if method == "PATCH":
                    proposal["state"] = "closed"
                return dict(proposal)
            if path == f"repos/{self.repo}/commits/master":
                return {"sha": baseline}
            if path == f"repos/{self.repo}/issues/70/comments" and method == "POST":
                return {"id": 900, "body": data["body"]}
            raise AssertionError((path, method))

        def git_run(*args, cwd=None, env=None, input=None):
            if args[:3] == ("git", "rev-parse", "FETCH_HEAD"):
                return reviewed_sha
            if args[:3] == ("git", "rev-parse", "HEAD"):
                return adopted_sha
            if args[:2] == ("git", "diff") and "--name-only" in args:
                return "\n".join(changed)
            if args[:2] == ("git", "push"):
                push_calls.append((args, env))
            return ""

        tree = {path: {"mode": "100644", "blob_sha": "b" * 40} for path in changed}
        owner_token = (patch.object(release, "owner_token", side_effect=token_error)
                       if missing_owner_token else
                       patch.object(release, "owner_token", return_value="fixture-owner-token"))
        with tempfile.TemporaryDirectory(prefix="osconfig-paired-adoption-") as temporary:
            root = Path(temporary)
            reviewed_dir, proposal_dir = root / "reviewed", root / "proposal"
            reviewed_dir.mkdir()
            proposal_dir.mkdir()
            (reviewed_dir / "candidate-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            with patch.dict(os.environ, {
                    "GITHUB_REPOSITORY": self.repo, "GITHUB_SHA": baseline,
                    "GITHUB_RUN_ID": "901", "GITHUB_RUN_ATTEMPT": "1",
                    "POLICY_PR_NUMBER": "70", "POLICY_HEAD_SHA": proposal_head,
                }, clear=True), \
                    patch.object(release, "review_pair_status",
                                 return_value=({}, {}, {"state": "ready", "complete": True})), \
                    patch.object(release, "current_final_reservation", return_value={"id": 1}), \
                    patch.object(release, "policy_identity",
                                 return_value={"head": proposal_head, "branch": branch}), \
                    patch.object(release, "policy_changes", return_value=list(changed)), \
                    patch.object(release, "git_tree_map", return_value=tree), \
                    patch.object(release, "validate_reviewed_adoption"), \
                    patch.object(release, "close_review_context_pair"), \
                    patch.object(release, "api", side_effect=api), \
                    patch.object(release, "run", side_effect=git_run), \
                    patch.object(release.subprocess, "check_output", return_value=b"reviewed policy diff"), \
                    patch.object(release.subprocess, "run",
                                 side_effect=lambda args, **_kwargs:
                                 subprocess.CompletedProcess(args, 0, b"", b"")), \
                    owner_token as token_mock:
                if missing_owner_token:
                    with self.assertRaisesRegex(ValueError, "fixture owner token unavailable"):
                        release.adopt_policy_pair(reviewed_dir, proposal_dir)
                else:
                    release.adopt_policy_pair(reviewed_dir, proposal_dir)

        return push_calls, api_calls, token_mock

    def test_paired_adoption_uses_owner_token_only_for_workflow_change(self):
        workflow = ".github/workflows/google-osconfig-agent-inventory.yml"
        ordinary = ".vps/google-osconfig-agent/patches/release.py"
        for changed, needs_owner_token in (([workflow], True), ([ordinary], False)):
            with self.subTest(changed=changed):
                push_calls, _api_calls, token_mock = self.invoke_adoption(changed)
                self.assertEqual(len(push_calls), 1)
                args, env = push_calls[0]
                self.assertEqual(args[:2], ("git", "push"))
                self.assertEqual((env or {}).get("GH_TOKEN"),
                                 "fixture-owner-token" if needs_owner_token else None)
                self.assertEqual(token_mock.call_count, 1 if needs_owner_token else 0)

    def test_paired_adoption_refuses_workflow_push_without_owner_token(self):
        workflow = ".github/workflows/google-osconfig-agent-inventory.yml"
        push_calls, api_calls, token_mock = self.invoke_adoption(
            [workflow], missing_owner_token=True)
        self.assertEqual(push_calls, [])
        token_mock.assert_called_once_with(self.repo)
        self.assertFalse(any(method == "POST" for _path, method in api_calls))


class AcceptedBaselineProofTests(unittest.TestCase):
    def test_checkpoint_must_match_the_verified_signed_deployment(self):
        repo = "warelik/osconfig"
        candidate = {
            "schema": 1, "repository": repo,
            "upstream_sha": "a" * 40, "application_sha": "b" * 40,
            "configuration_sha": "c" * 40, "patchset_sha256": "d" * 64,
            "recipe_sha256": "e" * 64, "platform": "fedora-44/x86_64",
        }
        baseline = {
            "candidate": candidate, "candidate_id": "f" * 64,
            "release_id": 701, "published_at": "2026-10-19T12:00:00Z",
            "manifest_sha256": "1" * 64,
        }
        value = {
            "schema": 1, "repository": repo, "candidate": candidate,
            "publication": {
                "kind": "signed-repository", "id": 701,
                "published_at": baseline["published_at"],
                "metadata_sha256": baseline["manifest_sha256"],
            },
        }
        variable = {
            "name": "FORK_ACCEPTED_BASELINE",
            "value": json.dumps(value, sort_keys=True, separators=(",", ":")),
            "created_at": "2026-10-19T12:01:00Z",
            "updated_at": "2026-10-19T12:01:00Z",
        }

        class Core:
            @staticmethod
            def candidate_identity(_candidate):
                return "f" * 64

        with patch.object(release, "lifecycle_module", return_value=Core()):
            proof = release.accepted_baseline_proof(repo, variable, baseline)
            self.assertEqual(proof["endpoint"],
                             "repos/warelik/osconfig/actions/variables/FORK_ACCEPTED_BASELINE")
            value["publication"]["metadata_sha256"] = "2" * 64
            variable["value"] = json.dumps(value, sort_keys=True, separators=(",", ":"))
            with self.assertRaisesRegex(ValueError, "differs from the latest verified"):
                release.accepted_baseline_proof(repo, variable, baseline)


class PackageIdentityTests(unittest.TestCase):
    marker = "# Managed by ~/.vps/google-osconfig-agent/install.sh; local edits are replaced on the next install."

    def test_only_one_primary_key_is_accepted_with_its_subkeys(self):
        fingerprint = "A" * 40
        output = f"pub::::::::::\nfpr:::::::::{fingerprint}:\nsub::::::::::\nfpr:::::::::{'B' * 40}:\n"
        with patch.object(release, "run", return_value=output):
            self.assertEqual(release.key_fingerprint(Path("public-key"), {}), fingerprint)

    def test_extra_primary_key_is_rejected(self):
        output = "".join(f"pub::::::::::\nfpr:::::::::{letter * 40}:\n" for letter in ("A", "B"))
        with patch.object(release, "run", return_value=output), self.assertRaisesRegex(ValueError, "exactly one"):
            release.key_fingerprint(Path("public-key"), {})

    def test_missing_or_malformed_primary_key_is_rejected(self):
        for output in ("", "pub::::::::::\nfpr:::::::::bad:\n"):
            with self.subTest(output=output), patch.object(release, "run", return_value=output), self.assertRaisesRegex(ValueError, "exactly one"):
                release.key_fingerprint(Path("public-key"), {})

    def write_config(self, root, *, minimum="0:20261015.00-1.vps0.fc44"):
        config = root / ".vps/google-osconfig-agent/repository.conf"
        config.parent.mkdir(parents=True)
        config.write_text(
            f"{self.marker}\n"
            "github_owner=owner\n"
            "github_repo=osconfig\n"
            "signing_fingerprint=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            f"minimum_evr={minimum}\n",
            encoding="utf-8",
        )
        return config

    def test_repository_delivery_config_is_validated_and_normalizes_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_config(root)
            with patch.object(release, "ROOT", root):
                settings = release.repository_settings()
        self.assertEqual(settings["github_owner"], "owner")
        self.assertEqual(settings["github_repo"], "osconfig")
        self.assertEqual(settings["signing_fingerprint"], "A" * 40)

    def test_unconfigured_delivery_values_block_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.write_config(root, minimum="__UNCONFIGURED__")
            config.write_text(
                config.read_text().replace("github_owner=owner", "github_owner=__UNCONFIGURED__"),
                encoding="utf-8",
            )
            with patch.object(release, "ROOT", root), self.assertRaisesRegex(ValueError, "invalid or unconfigured"):
                release.repository_settings()

    def test_native_rpm_evr_orders_upstream_tag_then_fork_release(self):
        self.assertLess(
            release.osconfig_evr_key("0:20261015.00-1.vps9.fc44"),
            release.osconfig_evr_key("0:20261015.00-1.vps10.fc44"),
        )
        self.assertLess(
            release.osconfig_evr_key("0:20260717.00-1.vps999.fc44"),
            release.osconfig_evr_key("0:20261015.00-1.vps1.fc44"),
        )

    def test_evr_rejects_a_different_package_release_layout(self):
        with self.assertRaisesRegex(ValueError, "Unsupported Fedora 44"):
            release.osconfig_evr_key("0:20261015.00-1.fc43")


class ProductRecipeIdentityTests(unittest.TestCase):
    def test_recipe_v3_hashes_all_six_actual_build_inputs(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-recipe-identity-") as temporary:
            root = Path(temporary)
            for relative in release.PRODUCT_RECIPE_INPUTS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"build input {relative}\n", encoding="utf-8")
            diagnostic = root / "check-upstream.sh"
            diagnostic.write_text("local diagnostic one\n", encoding="utf-8")

            baseline = release.recipe_digest(root)
            expected = hashlib.sha256(b"osconfig-rpm-recipe:v3\0")
            for relative in release.PRODUCT_RECIPE_INPUTS:
                expected.update(relative.encode("utf-8") + b"\0"
                                + (root / relative).read_bytes() + b"\0")
            self.assertEqual(baseline, expected.hexdigest())

            diagnostic.write_text("local diagnostic changed\n", encoding="utf-8")
            self.assertEqual(release.recipe_digest(root), baseline)
            for relative in release.PRODUCT_RECIPE_INPUTS:
                with self.subTest(relative=relative):
                    path = root / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"real build input changed\n")
                    self.assertNotEqual(release.recipe_digest(root), baseline)
                    path.write_bytes(original)

    def test_local_diagnostic_remains_in_policy_and_exact_regression_adoption(self):
        diagnostic = release.PREFIX + "check-upstream.sh"
        self.assertEqual(set(release.PRODUCT_BUILD_INPUTS), {
            "build-rpm.sh", "prepare-source.sh", "osconfig-inventory.patch",
            "rpm/google-osconfig-agent.spec", "rpm/go-vendor-tools.toml",
        })
        self.assertNotIn("check-upstream.sh", release.PRODUCT_BUILD_INPUTS)
        self.assertNotIn(diagnostic, release.FULL_PRODUCT_PATHS)
        self.assertIn("check-upstream.sh", release.PACKAGE_FILES)
        self.assertIn(diagnostic, release.POLICY_FILES)
        self.assertIn(diagnostic, release.REGRESSION_ADOPTION_PATHS)
        self.assertNotIn(diagnostic, release.PRODUCT_ADOPTION_PATHS)
        self.assertNotIn(diagnostic, release.EDITABLE_CANDIDATE_FILES)
        self.assertEqual(
            release.FULL_PRODUCT_PATHS,
            tuple(sorted(release.PREFIX + relative
                         for relative in (*release.PRODUCT_BUILD_INPUTS, "source.lock"))),
        )

        workflow_paths = (
            release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml",
            release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml",
        )
        for path in workflow_paths:
            with self.subTest(workflow=path):
                document = release.yaml_module().safe_load(path.read_text(encoding="utf-8"))
                commands = [step.get("run", "")
                            for job in document["jobs"].values()
                            for step in (job.get("steps") or [])]
                self.assertFalse(any("check-upstream.sh" in command for command in commands))
        build_script = (release.PATCH_DIR / "build-rpm.sh").read_text(encoding="utf-8")
        self.assertNotIn("check-upstream.sh", build_script)

    def test_application_input_reuse_ignores_modes_and_diagnostics_but_not_blobs(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-recipe-reuse-") as temporary:
            root = Path(temporary)
            repository = root / "repository"
            current = root / "current"
            repository.mkdir()
            current.mkdir()

            def git(*arguments):
                result = subprocess.run(["git", *arguments], cwd=repository, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        check=True)
                return result.stdout.strip()

            git("init")
            git("config", "user.name", "recipe fixture")
            git("config", "user.email", "recipe-fixture@example.invalid")
            for relative in release.PRODUCT_RECIPE_INPUTS:
                payload = f"stable bytes for {relative}\n".encode()
                source = repository / release.PREFIX / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(payload)
                target = current / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            old_script = repository / release.PREFIX / "build-rpm.sh"
            old_script.chmod(0o644)
            (current / "build-rpm.sh").chmod(0o755)
            git("add", "--all")
            git("commit", "-m", "product recipe")
            application_sha = git("rev-parse", "HEAD")
            diagnostic = current / "check-upstream.sh"
            diagnostic.write_text("diagnostic-only change\n", encoding="utf-8")

            with patch.object(release, "PATCH_DIR", current):
                self.assertTrue(release.candidate_product_inputs_match_application(
                    repository, application_sha, current))
                source_lock = current / "source.lock"
                original_lock = source_lock.read_bytes()
                source_lock.write_bytes(original_lock + b"tag changed\n")
                self.assertFalse(release.candidate_product_inputs_match_application(
                    repository, application_sha, current))
                source_lock.write_bytes(original_lock)
                (current / "rpm/go-vendor-tools.toml").write_bytes(b"changed vendor recipe\n")
                self.assertFalse(release.candidate_product_inputs_match_application(
                    repository, application_sha, current))


class PublicFrozenArtifactProvenanceTests(unittest.TestCase):
    def candidate(self):
        return {
            "schema": 1,
            "repository": "warelik/osconfig",
            "upstream_sha": "a" * 40,
            "application_sha": "a" * 40,
            "configuration_sha": "b" * 40,
            "patchset_sha256": "c" * 64,
            "recipe_sha256": "d" * 64,
            "platform": "fedora-44/x86_64",
        }

    def test_public_identity_matches_canonical_abi_and_rejects_malformed_candidates(self):
        candidate = self.candidate()
        canonical = hashlib.sha256(json.dumps(
            candidate, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual(release.frozen_candidate_identity(candidate), canonical)

        for mutation in (
                {**candidate, "extra": "unbound"},
                {**candidate, "schema": True},
                {**candidate, "platform": "macos/aarch64"},
                {**candidate, "recipe_sha256": "not-a-digest"},
        ):
            with self.subTest(candidate=mutation), self.assertRaisesRegex(
                    ValueError, "Frozen public candidate ABI is malformed"):
                release.frozen_candidate_identity(mutation)

    def test_build_provenance_uses_public_identity_without_private_loader(self):
        candidate = self.candidate()
        candidate_id = release.frozen_candidate_identity(candidate)
        candidate_sha = "e" * 40
        with tempfile.TemporaryDirectory(prefix="osconfig-public-build-proof-") as temporary:
            root = Path(temporary)
            candidate_dir = root / "candidate"
            built_dir = root / "built"
            candidate_dir.mkdir()
            built_dir.mkdir()
            (candidate_dir / "candidate-manifest.json").write_text(json.dumps({
                "candidate": candidate,
                "candidateIdentity": candidate_id,
                "candidateSha": candidate_sha,
            }), encoding="utf-8")
            rpm_path = built_dir / "rpm" / "google-osconfig-agent.rpm"
            rpm_path.parent.mkdir()
            rpm_path.write_bytes(b"exact build output")

            environment = {
                "EXPECTED_CANDIDATE_ID": candidate_id,
                "GITHUB_RUN_ID": "701",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_SHA": "f" * 40,
            }
            forbidden_loader = AssertionError("post-build provenance loaded private lifecycle code")
            with patch.dict(os.environ, environment), \
                    patch.object(release, "lifecycle_module", side_effect=forbidden_loader):
                release.write_build_provenance(candidate_dir, built_dir)

            proof = json.loads((built_dir / release.BUILD_PROVENANCE_FILE).read_text(encoding="utf-8"))
            self.assertEqual(proof["candidate_id"], candidate_id)
            self.assertEqual(proof["candidate_sha"], candidate_sha)
            self.assertEqual(proof["run_id"], 701)
            self.assertEqual(proof["run_attempt"], 2)
            self.assertEqual(proof["files"], {"rpm/google-osconfig-agent.rpm":
                                               hashlib.sha256(b"exact build output").hexdigest()})

            with patch.dict(os.environ, {**environment, "EXPECTED_CANDIDATE_ID": "9" * 64}), \
                    patch.object(release, "lifecycle_module", side_effect=forbidden_loader), \
                    self.assertRaisesRegex(ValueError, "exact reviewed candidate"):
                release.write_build_provenance(candidate_dir, built_dir)


class CandidateBuildInputIdentityTests(unittest.TestCase):
    upstream = "a" * 40
    candidate_id = "c" * 64
    workflow_sha = "d" * 40

    def candidate_directory(self, root):
        root.mkdir(parents=True, exist_ok=True)
        archive = b"exact selected upstream archive"
        archive_sha = hashlib.sha256(archive).hexdigest()
        (root / "source.tar.gz").write_bytes(archive)
        lock = {"tag": "20261015.00", "commit": self.upstream,
                "archiveSha256": archive_sha}
        (root / "source.lock").write_text(json.dumps(lock), encoding="utf-8")
        for relative in release.PRODUCT_BUILD_INPUTS:
            path = root / Path(relative).name
            path.write_bytes(f"candidate input {relative}\n".encode())
        candidate = {"upstream_sha": self.upstream,
                     "recipe_sha256": release.artifact_recipe_digest(root)}
        manifest = {"candidate": candidate, "candidateIdentity": self.candidate_id,
                    "upstreamTag": lock["tag"], "upstreamCommit": lock["commit"],
                    "upstreamArchiveSha256": lock["archiveSha256"], "candidatePr": 42}
        return candidate, manifest, lock

    def test_exact_flat_candidate_recipe_and_archive_lock_are_accepted(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-final-input-valid-") as temporary:
            root = Path(temporary)
            candidate, manifest, lock = self.candidate_directory(root)
            self.assertEqual(release.verify_candidate_build_inputs(candidate, manifest, root), lock)

    def test_candidate_recipe_and_source_lock_must_match_before_final_reservation(self):
        class Core:
            @staticmethod
            def candidate_identity(_candidate):
                return CandidateBuildInputIdentityTests.candidate_id

        with tempfile.TemporaryDirectory(prefix="osconfig-final-input-check-") as temporary:
            root = Path(temporary) / "candidate"
            candidate, manifest, _lock = self.candidate_directory(root)
            (root / "candidate-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (root / "go-vendor-tools.toml").write_bytes(b"changed after freeze\n")
            with patch.object(release, "lifecycle_module", return_value=Core), \
                    patch.object(release, "current_final_reservation") as reservation, \
                    patch.dict(os.environ, {
                        "GITHUB_REPOSITORY": "warelik/osconfig",
                        "GITHUB_RUN_ID": "701", "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_SHA": self.workflow_sha,
                    }), self.assertRaisesRegex(ValueError, "recipe differs"):
                release.verify_final_run(root, 701, 2, self.workflow_sha, self.candidate_id)
            reservation.assert_not_called()

    def test_final_recipe_validation_rejects_manifest_tag_commit_and_archive_drift(self):
        for field, value in (("upstreamTag", "20261016.00"),
                             ("upstreamCommit", "b" * 40),
                             ("upstreamArchiveSha256", "e" * 64)):
            with tempfile.TemporaryDirectory(prefix="osconfig-lock-identity-") as temporary:
                root = Path(temporary)
                candidate, manifest, _lock = self.candidate_directory(root)
                manifest[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "source lock"):
                    release.verify_candidate_build_inputs(candidate, manifest, root)

    def test_valid_final_candidate_reaches_native_reservation_check(self):
        class Core:
            @staticmethod
            def candidate_identity(_candidate):
                return CandidateBuildInputIdentityTests.candidate_id

        with tempfile.TemporaryDirectory(prefix="osconfig-final-input-valid-run-") as temporary:
            root = Path(temporary)
            candidate, manifest, _lock = self.candidate_directory(root)
            (root / "candidate-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with patch.object(release, "lifecycle_module", return_value=Core), \
                    patch.object(release, "current_final_reservation", return_value=True) as reservation, \
                    patch.dict(os.environ, {
                        "GITHUB_REPOSITORY": "warelik/osconfig",
                        "GITHUB_RUN_ID": "701", "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_SHA": self.workflow_sha,
                    }):
                release.verify_final_run(root, 701, 2, self.workflow_sha, self.candidate_id)
            reservation.assert_called_once_with(
                "warelik/osconfig", 42, candidate, 701, 2, self.workflow_sha)


class ExactShaReviewRegressionTests(unittest.TestCase):
    sha = ExactShaReviewTests.sha
    requested = ExactShaReviewTests.requested
    clean_native_comment = ExactShaReviewTests.clean_native_comment
    gate = ExactShaReviewTests.gate

    def test_relocated_old_inline_finding_requires_fresh_review_but_does_not_poison_it(self):
        inline = {"user": {"login": release.BOT, "type": "Bot"},
                  "commit_id": self.sha, "original_commit_id": "b" * 40,
                  "body": "P1 defect on an earlier commit"}
        self.assertFalse(self.gate(inline=[inline])[0])
        self.assertTrue(self.gate(comments=[self.clean_native_comment()], inline=[inline])[0])

    def test_original_current_inline_finding_still_blocks_when_relocated(self):
        inline = {"user": {"login": release.BOT, "type": "Bot"},
                  "commit_id": "b" * 40, "original_commit_id": self.sha,
                  "body": "P2 defect on the requested commit"}
        self.assertFalse(self.gate(comments=[self.clean_native_comment()], inline=[inline])[0])

    def test_exact_sha_inline_finding_blocks_even_with_clean_summary(self):
        inline = {
            "user": {"login": release.BOT, "type": "Bot"},
            "commit_id": self.sha,
            "body": "P2 suggestion",
        }
        ready, reason = self.gate(comments=[self.clean_native_comment()], inline=[inline])
        self.assertFalse(ready)
        self.assertIn("inline findings", reason)

    def test_native_clean_state_does_not_clear_a_reported_priority_finding(self):
        comment = self.clean_native_comment()
        comment["body"] += "\nP2: inventory architecture is still wrong"
        ready, reason = self.gate(comments=[comment])
        self.assertFalse(ready)
        self.assertIn("finding", reason)

    def test_approval_with_any_nonclean_body_does_not_pass(self):
        review = {
            "user": {"login": release.BOT, "type": "Bot"},
            "commit_id": self.sha,
            "submitted_at": "2026-10-17T12:10:00Z",
            "state": "APPROVED",
            "body": "Codex Review: Didn't find any major issues.\\nP2 suggestion",
        }
        ready, reason = self.gate(reviews=[review])
        self.assertFalse(ready)
        self.assertEqual(reason, release.WAITING)

    def test_clean_exact_review_body_is_accepted_without_severity_exception(self):
        review = {
            "user": {"login": release.BOT, "type": "Bot"},
            "commit_id": self.sha,
            "submitted_at": "2026-10-17T12:10:00Z",
            "state": "APPROVED",
            "body": "Codex Review: Didn't find any major issues.",
        }
        ready, reason = self.gate(reviews=[review])
        self.assertTrue(ready, reason)

    def test_owner_request_must_exist_after_review_cycle_starts(self):
        review = {
            "user": {"login": release.BOT, "type": "Bot"},
            "commit_id": self.sha,
            "submitted_at": "2026-10-17T11:00:00Z",
            "state": "APPROVED",
            "body": "Codex Review: Didn't find any major issues.",
        }
        ready, reason = self.gate(reviews=[review])
        self.assertFalse(ready)
        self.assertEqual(reason, release.WAITING)


class BoundedContinuationTests(unittest.TestCase):
    sha = "a" * 40
    other_sha = "b" * 40
    cycle = "c" * 40 + ":" + "d" * 40
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)

    def fix_comment(self, sha, timestamp, created_at):
        state = {"cycle": self.cycle, "startedAt": self.start.isoformat()}
        return {
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "body": (f"<!-- osconfig-fix-cycle:v1 {json.dumps(state)} -->\n"
                     f"<!-- osconfig-fix-window:v1 {sha} {int(timestamp.timestamp())} -->"),
        }

    def test_first_repair_task_starts_a_cycle_and_is_due(self):
        now = self.start
        state = release.repair_attempt_state([], cycle=self.cycle, sha=self.sha, now=now)
        self.assertTrue(state["due"])
        self.assertEqual(state["attempt"], 1)
        self.assertEqual(state["started_at"], now.isoformat())

    def test_elapsed_window_continues_without_owner_escalation_or_cycle_reset(self):
        prior = self.fix_comment(self.sha, self.start, self.start)
        active = release.repair_attempt_state(
            [prior], cycle=self.cycle, sha=self.sha,
            now=self.start + timedelta(seconds=release.REPAIR_WINDOW_SECONDS - 1),
        )
        self.assertFalse(active["due"])
        resumed = release.repair_attempt_state(
            [prior], cycle=self.cycle, sha=self.sha,
            now=self.start + timedelta(seconds=release.REPAIR_WINDOW_SECONDS),
        )
        self.assertTrue(resumed["due"])
        self.assertEqual(resumed["started_at"], self.start.isoformat())
        self.assertEqual(resumed["attempt"], 2)

    def test_new_candidate_sha_continues_attempt_history_immediately(self):
        prior = self.fix_comment(self.sha, self.start, self.start)
        resumed = release.repair_attempt_state(
            [prior], cycle=self.cycle, sha=self.other_sha,
            now=self.start + timedelta(minutes=5),
        )
        self.assertTrue(resumed["due"])
        self.assertEqual(resumed["started_at"], self.start.isoformat())
        self.assertEqual(resumed["attempt"], 2)

    def test_review_followup_waits_a_window_and_restarts_only_its_window(self):
        request = {"created_at": self.start.isoformat().replace("+00:00", "Z"),
                   "body": f"@codex review <!-- osconfig-codex:{self.sha} -->"}
        self.assertFalse(release.review_followup_due(
            [request], sha=self.sha,
            now=self.start + timedelta(seconds=release.REPAIR_WINDOW_SECONDS - 1)))
        now = self.start + timedelta(seconds=release.REPAIR_WINDOW_SECONDS)
        self.assertTrue(release.review_followup_due([request], sha=self.sha, now=now))
        followup = {"created_at": now.isoformat().replace("+00:00", "Z"),
                    "body": f"<!-- osconfig-review-window:v1 {self.sha} {int(now.timestamp())} -->"}
        self.assertFalse(release.review_followup_due([request, followup], sha=self.sha,
                                                     now=now + timedelta(seconds=1)))
        self.assertTrue(release.review_followup_due([request, followup], sha=self.sha,
                                                    now=now + timedelta(seconds=release.REPAIR_WINDOW_SECONDS)))


class PendingApplicationScopeContinuationTests(unittest.TestCase):
    repo = "owner/osconfig"
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)

    def fixture(self):
        contexts = {
            "full": {"pr": 11, "review_sha": "a" * 40, "base_sha": "d" * 40},
            "delta": {"pr": 12, "review_sha": "b" * 40, "base_sha": "e" * 40},
        }
        manifest = {"candidateIdentity": "c" * 64, "reviewContexts": contexts,
                    "candidate": {"upstream_sha": "f" * 40, "application_sha": "a" * 40,
                                  "configuration_sha": "b" * 40, "patchset_sha256": "d" * 64,
                                  "recipe_sha256": "e" * 64}}
        comments, pulls = {}, {}
        for scope, context in contexts.items():
            number = context["pr"]
            stamp = self.start.isoformat().replace("+00:00", "Z")
            comments[number] = [{"id": number, "user": {"login": "owner", "type": "User"},
                                 "created_at": stamp, "updated_at": stamp,
                                 "body": release.owner_review_marker("c" * 64, scope,
                                              context["review_sha"], context["base_sha"])}]
            pulls[number] = {"number": number, "state": "open",
                             "head": {"sha": context["review_sha"], "repo": {"full_name": self.repo}},
                             "base": {"sha": context["base_sha"], "repo": {"full_name": self.repo}}}
        return manifest, comments, pulls

    def test_only_stalled_unfinished_scope_gets_one_followup_per_window(self):
        manifest, comments, pulls = self.fixture()
        now = self.start + timedelta(seconds=release.REPAIR_WINDOW_SECONDS)
        posts = []
        def api(route, **kwargs):
            if kwargs.get("method") == "POST":
                number = int(route.split("/")[-2])
                body = kwargs["data"]["body"]
                stamp = now.isoformat().replace("+00:00", "Z")
                comments[number].append({"id": 100 + len(posts), "body": body,
                    "user": {"login": "owner", "type": "User"},
                    "created_at": stamp, "updated_at": stamp})
                posts.append((number, body))
                return comments[number][-1]
            return pulls[int(route.rsplit("/", 1)[-1])]
        def pages(route):
            return comments[int(route.split("/")[-2])]
        with patch.object(release, "api", side_effect=api), patch.object(release, "pages", side_effect=pages):
            release.continue_pending_lifecycle_reviews(self.repo, manifest,
                {"complete": True}, {"complete": False}, "token", now=now - timedelta(seconds=1))
            self.assertEqual(posts, [])
            release.continue_pending_lifecycle_reviews(self.repo, manifest,
                {"complete": True}, {"complete": False}, "token", now=now)
            self.assertEqual([n for n, _ in posts], [12])
            self.assertIn("<!-- osconfig-review-window:v1 " + "b" * 40, posts[0][1])
            release.continue_pending_lifecycle_reviews(self.repo, manifest,
                {"complete": True}, {"complete": False}, "token", now=now + timedelta(seconds=1))
            self.assertEqual(len(posts), 1)
            now += timedelta(seconds=release.REPAIR_WINDOW_SECONDS)
            release.continue_pending_lifecycle_reviews(self.repo, manifest,
                {"complete": True}, {"complete": False}, "token", now=now)
            self.assertEqual([n for n, _ in posts], [12, 12])

    def test_changed_native_head_refuses_followup(self):
        manifest, comments, pulls = self.fixture()
        pulls[12]["head"]["sha"] = "9" * 40
        with patch.object(release, "api", return_value=pulls[12]) as api, \
                patch.object(release, "pages", return_value=comments[12]):
            with self.assertRaisesRegex(ValueError, "exact native source/base"):
                release.continue_pending_lifecycle_reviews(self.repo, manifest,
                    {"complete": True}, {"complete": False}, "token",
                    now=self.start + timedelta(seconds=release.REPAIR_WINDOW_SECONDS))
        self.assertFalse(any(call.kwargs.get("method") == "POST" for call in api.call_args_list))


class BuildInfrastructureFailureRoutingTests(unittest.TestCase):
    def test_classifier_routes_unlisted_failures_without_hiding_application_failure(self):
        workflow = (release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml").read_text()
        block = workflow.split("      - name: Classify the failed stage", 1)[1].split("\n  review:", 1)[0]
        shell = block.split("        run: |\n", 1)[1]
        shell = "\n".join(line[10:] for line in shell.splitlines())
        cases = [({"BUILD_JOB_STATUS": "failure", "BUILD_OUTCOME": "skipped"}, "publisher"),
                 ({"BUILD_JOB_STATUS": "failure", "BUILD_OUTCOME": "failure"}, "application"),
                 ({"BUILD_JOB_STATUS": "failure", "BUILD_OUTCOME": "success",
                   "PROVENANCE_OUTCOME": "failure"}, "publisher"),
                 ({"BUILD_JOB_STATUS": "success", "BUILD_OUTCOME": "success"}, "none")]
        for changed, expected in cases:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "output"
                env = {**os.environ, "PREFLIGHT_OUTCOME": "success", "TOOLS_OUTCOME": "success",
                       "ARTIFACT_OUTCOME": "skipped", "PROVENANCE_OUTCOME": "skipped",
                       "GITHUB_OUTPUT": str(output), **changed}
                subprocess.run(["bash", "-e", "-c", shell], env=env, check=True)
                self.assertEqual(output.read_text(), "failure_class=" + expected + "\n")
        self.assertIn("needs.build-rpm.result == 'failure' && needs.build-rpm.outputs.failure_class != 'application'", workflow)


class PublisherPolicyScopeTests(unittest.TestCase):
    def test_private_checkout_guards_match_git_normalized_ssh_config_key(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-git-config-key-") as temporary:
            config = Path(temporary) / "config"
            subprocess.run(["git", "config", "--file", str(config),
                            "core.sshCommand", "ssh -i /tmp/fixture-key"], check=True)
            names = subprocess.run(
                ["git", "config", "--file", str(config), "--name-only", "--list"],
                check=True, stdout=subprocess.PIPE, text=True).stdout.splitlines()
        self.assertIn("core.sshcommand", names)
        self.assertNotIn("core.sshCommand", names)

        installed = (release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml").read_text(
            encoding="utf-8")
        template = (release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml").read_text(
            encoding="utf-8")
        self.assertEqual(installed, template)
        guards = [line for line in installed.splitlines()
                  if "config --local --get-regexp" in line]
        self.assertEqual(len(guards), 16)
        self.assertTrue(all(r"core\.sshcommand" in line for line in guards))
        self.assertFalse(any(r"core\.sshCommand" in line for line in guards))

    def test_scoped_cleanup_owns_only_unique_head_refs_for_the_exact_pair(self):
        upstream, source_config, baseline_config = "a" * 40, "b" * 40, "c" * 40
        source_pair_key = hashlib.sha256(
            (source_config + "\0" + baseline_config).encode("utf-8")).hexdigest()
        full_ref = f"review/{upstream}-{source_pair_key}"
        delta_ref, candidate_ref = "review/changes-" + "d" * 40, f"review/{upstream}-" + "e" * 64
        pulls = [
            {"number": 91, "head": {"ref": full_ref}},
            {"number": 92, "head": {"ref": delta_ref}},
            {"number": 93, "head": {"ref": "review/other-candidate"}},
            {"number": 94, "head": {"ref": full_ref}},
            {"number": 95, "head": {"ref": candidate_ref}},
            {"number": 96, "head": {"ref": "review-base/" + upstream}},
        ]
        self.assertEqual(release._owned_review_head_refs(pulls[:3], {91, 92}),
                         {full_ref, delta_ref})
        self.assertEqual(release._owned_review_head_refs(pulls, {91, 92}), {delta_ref})

    def test_release_policy_files_are_separate_from_application_patch(self):
        expected = {
            ".vps/google-osconfig-agent/patches/release.py",
            ".vps/google-osconfig-agent/patches/README.md",
            ".vps/google-osconfig-agent/patches/maintenance.py",
            ".vps/google-osconfig-agent/patches/maintenance.lock.json",
            ".vps/google-osconfig-agent/patches/tests/test_release.py",
            ".vps/google-osconfig-agent/patches/tests/test_policy_isolation.py",
            ".vps/google-osconfig-agent/patches/tests/test_maintenance_adapter.py",
            ".vps/google-osconfig-agent/patches/tests/test_upstream_source_isolation.py",
            ".vps/google-osconfig-agent/patches/tests/signing.sh",
            ".vps/google-osconfig-agent/patches/check-upstream.sh",
            ".vps/google-osconfig-agent/patches/sign-repo.sh",
            ".vps/google-osconfig-agent/patches/verify-repo.sh",
            ".vps/google-osconfig-agent/patches/workflows/google-osconfig-agent-inventory.yml",
            ".vps/google-osconfig-agent/patches/requirements-policy.txt",
            ".vps/google-osconfig-agent/patches/requirements-policy-bootstrap.txt",
            ".github/workflows/google-osconfig-agent-inventory.yml",
        }
        self.assertEqual(release.POLICY_FILES, expected)
        allowed = sorted(expected)
        self.assertEqual(release.validate_policy_paths([allowed[0]]), [allowed[0]])
        adapter_test = ".vps/google-osconfig-agent/patches/tests/test_maintenance_adapter.py"
        self.assertEqual(release.validate_policy_paths([adapter_test]), [adapter_test])
        diagnostic = ".vps/google-osconfig-agent/patches/check-upstream.sh"
        self.assertEqual(release.validate_policy_paths([diagnostic]), [diagnostic])
        source_isolation = release.PREFIX + "tests/test_upstream_source_isolation.py"
        self.assertIn(source_isolation, release.POLICY_FILES)
        self.assertNotIn("tests/test_upstream_source_isolation.py", release.PACKAGE_FILES)
        self.assertEqual(release.validate_policy_paths([source_isolation]), [source_isolation])
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            release.validate_policy_paths([
                ".vps/google-osconfig-agent/patches/release.py",
                ".vps/google-osconfig-agent/patches/osconfig-inventory.patch",
            ])
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            release.validate_policy_paths([])

    def test_signing_code_is_trusted_policy_not_application_candidate_input(self):
        for relative in ("sign-repo.sh", "verify-repo.sh"):
            with self.subTest(relative=relative):
                self.assertNotIn(relative, release.PACKAGE_FILES)
                self.assertNotIn(release.PREFIX + relative, release.EDITABLE_CANDIDATE_FILES)
                self.assertIn(release.PREFIX + relative, release.POLICY_FILES)
        self.assertIn(release.PREFIX + "tests/signing.sh", release.POLICY_FILES)

    def test_human_setup_notice_requires_a_concrete_permission_error(self):
        self.assertEqual(release.permission_blocker("repair window expired; try a new approach"), ("", ""))
        self.assertEqual(
            release.permission_blocker("CODEX_REQUEST_TOKEN is missing; no native Codex task was requested")[0],
            "owner Codex authorization",
        )
        self.assertEqual(
            release.permission_blocker("Resource not accessible by integration")[0],
            "GitHub Actions permission",
        )


class PublisherPolicyDiffTests(unittest.TestCase):
    def git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=cwd, check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

    def test_cached_whitespace_check_excludes_only_the_nested_source_patch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            self.git("init", str(work), cwd=root)
            self.git("config", "user.name", "test", cwd=work)
            self.git("config", "user.email", "test@example.invalid", cwd=work)
            source_file = work / "example.go"
            source_file.write_text("package p\nfunc f() {\n\tkeep()\n\treturn 1\n\n}\n", encoding="utf-8")
            self.git("add", "--", "example.go", cwd=work)
            self.git("commit", "-m", "nested patch source", cwd=work)
            nested_patch = work / release.PATCH_REL
            nested_patch.parent.mkdir(parents=True)
            nested_patch.write_text(
                "diff --git a/example.go b/example.go\n"
                "index 1111111..2222222 100644\n"
                "--- a/example.go\n"
                "+++ b/example.go\n"
                "@@ -1,6 +1,6 @@\n"
                " package p\n"
                " func f() {\n"
                " \tkeep()\n"
                "-\treturn 1\n"
                "+\treturn 2\n"
                " \n"
                " }\n",
                encoding="utf-8",
            )
            clean_file = work / "clean.txt"
            clean_file.write_text("clean\n", encoding="utf-8")
            self.git("add", "--all", cwd=work)
            self.assertEqual(
                subprocess.run(["git", "apply", "--check", str(nested_patch)], cwd=work,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode,
                0,
            )
            with self.assertRaises(subprocess.CalledProcessError):
                subprocess.run(["git", "diff", "--cached", "--check"], cwd=work, check=True,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            release.check_cached_whitespace(work)

            bad_file = work / "bad.txt"
            bad_file.write_text("ordinary whitespace error \n", encoding="utf-8")
            self.git("add", "--", "bad.txt", cwd=work)
            with self.assertRaises(subprocess.CalledProcessError):
                release.check_cached_whitespace(work)

    def test_adopt_uses_cached_whitespace_check_and_declared_package_modes(self):
        package_evr = next(
            line.partition("=")[2]
            for line in (release.ROOT / release.REPOSITORY_CONF).read_text(encoding="utf-8").splitlines()
            if line.startswith("minimum_evr=")
        )

        def run_adoption(root, *, bad_ordinary_file, base_script_mode):
            remote, seed = root / "origin.git", root / "seed"
            self.git("init", "--bare", "--initial-branch=master", str(remote), cwd=root)
            self.git("init", "--initial-branch=master", str(seed), cwd=root)
            self.git("config", "user.name", "adoption fixture", cwd=seed)
            self.git("config", "user.email", "adoption-fixture@example.invalid", cwd=seed)
            repository_conf = seed / release.REPOSITORY_CONF
            repository_conf.parent.mkdir(parents=True)
            repository_conf.write_bytes((release.ROOT / release.REPOSITORY_CONF).read_bytes())
            base_script = seed / release.PREFIX / "check-upstream.sh"
            base_script.parent.mkdir(parents=True, exist_ok=True)
            base_script.write_bytes(b"#!/usr/bin/env bash\n")
            base_script.chmod(base_script_mode)
            self.git("add", "--all", cwd=seed)
            self.git("commit", "-m", "trusted base", cwd=seed)
            config_sha = self.git("rev-parse", "HEAD", cwd=seed)
            self.git("push", str(remote), "HEAD:master", cwd=seed)

            candidate = root / "candidate"
            candidate.mkdir()
            for relative in release.PACKAGE_FILES:
                # Keep deterministic data independent of package inputs, including
                # a real unified diff with blank context for the whitespace guard.
                if relative == "osconfig-inventory.patch":
                    payload = (b"--- a/example.txt\n+++ b/example.txt\n"
                               b"@@ -1,2 +1,2 @@\n \n-before\n+after\n")
                else:
                    payload = f"fixture for {relative}\n".encode()
                if bad_ordinary_file and relative == "build-rpm.sh":
                    payload += b"# ordinary trailing whitespace \n"
                candidate_file = candidate / Path(relative).name
                candidate_file.write_bytes(payload)
                candidate_file.chmod(0o644)
            self.assertEqual((candidate / "check-upstream.sh").stat().st_mode & 0o777, 0o644)

            manifest = {"configSha": config_sha, "candidatePr": 42}
            settings = {"minimum_evr": package_evr}
            published = {"packageEvr": package_evr}
            verified = ("fixture/osconfig", manifest, settings, "A" * 40, published, config_sha)
            original_run = release.run

            def fixture_run(*arguments, cwd=None, env=None, input=None):
                if arguments == ("gh", "auth", "setup-git"):
                    return ""
                if arguments[:3] == ("git", "clone", "--no-checkout"):
                    arguments = (*arguments[:3], str(remote), arguments[4])
                    output = original_run(*arguments, cwd=cwd, env=env, input=input)
                    original_run("git", "config", "core.hooksPath", "/dev/null",
                                 cwd=arguments[4])
                    return output
                return original_run(*arguments, cwd=cwd, env=env, input=input)

            with patch.object(release, "verify_candidate_artifact", return_value=verified), \
                 patch.object(release, "run", side_effect=fixture_run), \
                 patch.object(release, "close_candidate"), \
                 patch.object(release, "owner_token",
                              return_value="fixture-owner-token") as owner_token, \
                 patch.object(release, "advance_accepted_baseline") as advance_baseline, \
                 patch.object(release, "check_cached_whitespace",
                              wraps=release.check_cached_whitespace) as whitespace_check, \
                 patch.dict(os.environ, {}, clear=False):
                if bad_ordinary_file:
                    with self.assertRaises(release.CommandFailure):
                        release.adopt(candidate, root / "pages")
                    owner_token.assert_not_called()
                    advance_baseline.assert_not_called()
                else:
                    release.adopt(candidate, root / "pages")
                    owner_token.assert_called_once_with(verified[0])
                    advance_baseline.assert_called_once_with(
                        verified[0], manifest, published, "fixture-owner-token")
            self.assertEqual(whitespace_check.call_count, 1)
            adopted_sha = self.git("--git-dir", str(remote), "rev-parse", "refs/heads/master",
                                   cwd=root)
            if bad_ordinary_file:
                return config_sha, adopted_sha, None, None

            def tree_mode(relative):
                entry = self.git("--git-dir", str(remote), "ls-tree", "-r", adopted_sha,
                                 "--", release.PREFIX + relative, cwd=root)
                return entry.split(maxsplit=1)[0]

            return config_sha, adopted_sha, tree_mode("check-upstream.sh"), tree_mode("source.lock")

        for base_script_mode in (0o755, 0o644):
            with self.subTest(base_script_mode=oct(base_script_mode)), \
                 tempfile.TemporaryDirectory(prefix="osconfig-adopt-whitespace-positive-") as temporary:
                root = Path(temporary)
                base_sha, adopted_sha, script_mode, data_mode = run_adoption(
                    root, bad_ordinary_file=False, base_script_mode=base_script_mode)
                self.assertNotEqual(adopted_sha, base_sha)
                self.assertEqual(self.git("--git-dir", str(root / "origin.git"), "show", "-s",
                                          "--format=%P", adopted_sha, cwd=root), base_sha)
                self.assertEqual(script_mode, "100755")
                self.assertEqual(data_mode, "100644")

        with tempfile.TemporaryDirectory(prefix="osconfig-adopt-whitespace-negative-") as temporary:
            root = Path(temporary)
            base_sha, adopted_sha, _, _ = run_adoption(
                root, bad_ordinary_file=True, base_script_mode=0o755)
            self.assertEqual(adopted_sha, base_sha)

    def test_exact_git_diff_accepts_only_regular_policy_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote, work = root / "remote.git", root / "work"
            self.git("init", "--bare", str(remote), cwd=root)
            self.git("init", str(work), cwd=root)
            self.git("config", "user.name", "test", cwd=work)
            self.git("config", "user.email", "test@example.invalid", cwd=work)
            self.git("remote", "add", "origin", str(remote), cwd=work)
            for relative in release.POLICY_FILES - {".github/workflows/google-osconfig-agent-inventory.yml"}:
                path = work / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("trusted policy input\n", encoding="utf-8")
            (work / (release.PREFIX + "release.py")).chmod(0o755)
            self.git("add", "--all", cwd=work)
            self.git("commit", "-m", "trusted config", cwd=work)
            seed = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", "HEAD:refs/heads/master", cwd=work)

            release_file = work / (release.PREFIX + "release.py")
            release_file.write_text("proposed policy\n", encoding="utf-8")
            self.git("add", "--", release.PREFIX + "release.py", cwd=work)
            self.git("commit", "-m", "policy change", cwd=work)
            allowed_head = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", f"{allowed_head}:refs/heads/proposal", cwd=work)
            self.assertEqual(
                release.policy_changes(work, seed, allowed_head),
                [release.PREFIX + "release.py"],
            )

            release_file.chmod(0o644)
            self.git("add", "--", release.PREFIX + "release.py", cwd=work)
            self.git("commit", "-m", "change policy mode", cwd=work)
            mode_head = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", f"{mode_head}:refs/heads/mode-change", cwd=work)
            with self.assertRaisesRegex(ValueError, "cannot change policy file mode"):
                release.policy_changes(work, seed, mode_head)

            self.git("checkout", "--detach", allowed_head, cwd=work)

            app_patch = work / (release.PREFIX + "osconfig-inventory.patch")
            app_patch.write_text("application change\n", encoding="utf-8")
            self.git("add", "--", release.PREFIX + "osconfig-inventory.patch", cwd=work)
            self.git("commit", "-m", "mixed application change", cwd=work)
            mixed_head = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", f"{mixed_head}:refs/heads/mixed", cwd=work)
            with self.assertRaisesRegex(ValueError, "allowlisted"):
                release.policy_changes(work, seed, mixed_head)

    def test_policy_diff_removes_shallow_boundary_before_ancestry_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote, source, shallow = root / "remote.git", root / "source", root / "shallow"
            self.git("init", "--bare", str(remote), cwd=root)
            self.git("init", str(source), cwd=root)
            self.git("config", "user.name", "test", cwd=source)
            self.git("config", "user.email", "test@example.invalid", cwd=source)
            self.git("remote", "add", "origin", str(remote), cwd=source)
            policy = source / (release.PREFIX + "release.py")
            policy.parent.mkdir(parents=True)
            policy.write_text("trusted\n", encoding="utf-8")
            policy.chmod(0o755)
            self.git("add", "--all", cwd=source)
            self.git("commit", "-m", "trusted", cwd=source)
            config = self.git("rev-parse", "HEAD", cwd=source)
            policy.write_text("proposed\n", encoding="utf-8")
            self.git("commit", "-am", "proposal", cwd=source)
            head = self.git("rev-parse", "HEAD", cwd=source)
            self.git("push", "origin", "HEAD:refs/heads/proposal", cwd=source)

            self.git("clone", "--depth=1", "--branch", "proposal",
                     "file://" + str(remote), str(shallow), cwd=root)
            self.assertEqual(self.git("rev-parse", "--is-shallow-repository", cwd=shallow), "true")
            self.assertEqual(release.policy_changes(shallow, config, head),
                             [release.PREFIX + "release.py"])
            self.assertEqual(self.git("rev-parse", "--is-shallow-repository", cwd=shallow), "false")

    def test_policy_change_cannot_replace_a_regular_file_with_a_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote, work = root / "remote.git", root / "work"
            self.git("init", "--bare", str(remote), cwd=root)
            self.git("init", str(work), cwd=root)
            self.git("config", "user.name", "test", cwd=work)
            self.git("config", "user.email", "test@example.invalid", cwd=work)
            self.git("remote", "add", "origin", str(remote), cwd=work)
            target = work / (release.PREFIX + "release.py")
            target.parent.mkdir(parents=True)
            target.write_text("trusted\n", encoding="utf-8")
            self.git("add", "--all", cwd=work)
            self.git("commit", "-m", "trusted config", cwd=work)
            seed = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", "HEAD:refs/heads/master", cwd=work)
            target.unlink()
            target.symlink_to("../../outside")
            self.git("add", "--all", cwd=work)
            self.git("commit", "-m", "symlink proposal", cwd=work)
            head = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", f"{head}:refs/heads/proposal", cwd=work)
            with self.assertRaisesRegex(ValueError, "regular tracked file"):
                release.policy_changes(work, seed, head)


class ReviewFindingBatchWriterTests(unittest.TestCase):
    repo = "warelik/osconfig"

    def candidate(self, configuration_sha="b" * 40):
        return {
            "schema": 1, "repository": self.repo,
            "upstream_sha": "a" * 40, "application_sha": "b" * 40,
            "configuration_sha": configuration_sha,
            "patchset_sha256": "c" * 64, "recipe_sha256": "d" * 64,
            "platform": "fedora-44/x86_64",
        }

    def contexts(self, candidate):
        return {
            "full": {"pr": 91, "review_sha": candidate["application_sha"],
                     "base_sha": candidate["upstream_sha"],
                     "head_branch": "review/full", "base_branch": "review-base/full"},
            "delta": {"pr": 92, "review_sha": candidate["configuration_sha"],
                      "base_sha": "e" * 40,
                      "head_branch": "review/changes", "base_branch": "review-base/delta"},
        }

    @staticmethod
    def finding(candidate, finding_id="inline:91:701", body="Lost inventory state", line=42):
        return {"finding_id": finding_id,
                "candidate_id": release.frozen_candidate_identity(candidate),
                "scope": "full", "source": "inline",
                "source_sha": candidate["application_sha"], "native_id": 701,
                "body": body, "line": line}

    def call_writer(self, candidate, contexts, findings, comments, posts):
        class Core:
            @staticmethod
            def candidate_identity(value):
                return release.frozen_candidate_identity(value)

        def api(route, *, method="GET", token=None, data=None, **_kwargs):
            if method != "POST":
                raise AssertionError(f"Unexpected API method/route: {method} {route}")
            post = {"id": 700 + len(posts) + 1,
                    "user": {"login": "warelik", "type": "User", "id": 17},
                    "created_at": "2026-10-20T10:00:00Z",
                    "updated_at": "2026-10-20T10:00:00Z",
                    "body": data["body"]}
            posts.append(post)
            comments.append(post)
            return post

        pair = {"complete": True, "observed_findings": findings}
        with patch.object(release, "lifecycle_module", return_value=Core), \
                patch.object(release, "pages", return_value=comments), \
                patch.object(release, "api", side_effect=api):
            release.record_review_finding_batch(
                self.repo, 91, candidate, contexts, pair, "owner-token")

    def test_exact_repeat_dedupes_but_new_candidate_or_changed_batch_posts(self):
        comments, posts = [], []
        candidate = self.candidate()
        contexts = self.contexts(candidate)
        findings = [self.finding(candidate)]
        self.call_writer(candidate, contexts, findings, comments, posts)
        self.call_writer(candidate, contexts, findings, comments, posts)
        self.assertEqual(len(posts), 1)

        other_candidate = self.candidate("f" * 40)
        self.call_writer(other_candidate, self.contexts(other_candidate),
                         [self.finding(other_candidate)], comments, posts)
        self.assertEqual(len(posts), 2)

        changed_findings = [self.finding(candidate, body="The corrected state is also lost")]
        self.call_writer(candidate, contexts, changed_findings, comments, posts)
        self.assertEqual(len(posts), 3)

    def test_exact_repeat_with_native_p1_badge_body_posts_once(self):
        comments, posts = [], []
        candidate = self.candidate()
        contexts = self.contexts(candidate)
        findings = [self.finding(
            candidate, body="<sub>![P1 Badge]</sub> The item is missing. <!-- marker -->")]
        self.call_writer(candidate, contexts, findings, comments, posts)
        self.call_writer(candidate, contexts, findings, comments, posts)
        self.assertEqual(len(posts), 1)
        self.assertIn("\\u003csub\\u003e", posts[0]["body"])

    def test_protocol_text_nested_in_another_marker_does_not_dedupe_a_batch(self):
        candidate = self.candidate()
        contexts = self.contexts(candidate)
        findings = [self.finding(candidate)]
        marker_value = {"schema": 1,
                        "candidate_id": release.frozen_candidate_identity(candidate),
                        "candidate": candidate, "review_contexts": contexts,
                        "findings": findings}
        encoded = json.dumps(marker_value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")
        nested_marker = "<!-- fork-finding-batch:v1 " + encoded + " -->"
        owner_comment = {"id": 900, "user": {"login": "warelik", "type": "User", "id": 17},
                         "created_at": "2026-10-20T09:00:00Z",
                         "updated_at": "2026-10-20T09:00:00Z",
                         "body": "<!-- fork-policy-pair:v1 "
                                 + json.dumps({"quoted": nested_marker}) + " -->"}
        comments, posts = [owner_comment], []
        self.call_writer(candidate, contexts, findings, comments, posts)
        self.assertEqual(len(posts), 1)

    def test_numeric_line_types_are_not_collapsed_by_python_value_equality(self):
        candidate = self.candidate()
        contexts = self.contexts(candidate)
        current_findings = [self.finding(candidate, line=42)]
        old_findings = [self.finding(candidate, line=42.0)]
        marker_value = {"schema": 1,
                        "candidate_id": release.frozen_candidate_identity(candidate),
                        "candidate": candidate, "review_contexts": contexts,
                        "findings": old_findings}
        encoded = json.dumps(marker_value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")
        owner_comment = {"id": 900, "user": {"login": "warelik", "type": "User", "id": 17},
                         "created_at": "2026-10-20T09:00:00Z",
                         "updated_at": "2026-10-20T09:00:00Z",
                         "body": release.FINDING_BATCH_PROLOGUE + "\\n\\n"
                                 + "<!-- fork-finding-batch:v1 " + encoded + " -->"}
        comments, posts = [owner_comment], []
        self.call_writer(candidate, contexts, current_findings, comments, posts)
        self.assertEqual(len(posts), 1)

    def test_malformed_duplicate_or_edited_owner_batch_fails_closed(self):
        candidate = self.candidate()
        contexts = self.contexts(candidate)
        findings = [self.finding(candidate)]
        marker_value = {"schema": 1,
                        "candidate_id": release.frozen_candidate_identity(candidate),
                        "candidate": candidate, "review_contexts": contexts,
                        "findings": findings}
        encoded = json.dumps(marker_value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")
        marker = "<!-- fork-finding-batch:v1 " + encoded + " -->"
        cases = (
            ({"body": release.FINDING_BATCH_PROLOGUE + "\\n\\n"
                     + "<!-- fork-finding-batch:v1 {bad -->"}, "malformed"),
            ({"body": release.FINDING_BATCH_PROLOGUE + "\\n\\n" + marker + "\\n" + marker},
             "duplicate"),
            ({"body": release.FINDING_BATCH_PROLOGUE + "\\n\\n" + marker,
              "updated_at": "2026-10-20T10:01:00Z"}, "edited"),
        )
        for override, label in cases:
            with self.subTest(label=label):
                existing = {"id": 901, "user": {"login": "warelik", "type": "User", "id": 17},
                            "created_at": "2026-10-20T10:00:00Z",
                            "updated_at": "2026-10-20T10:00:00Z", **override}
                comments, posts = [existing], []
                with self.assertRaises(ValueError):
                    self.call_writer(candidate, contexts, findings, comments, posts)
                self.assertEqual(posts, [])


class FindingDispositionReceiptTests(unittest.TestCase):
    repo = "warelik/osconfig"
    old_app = "a" * 40
    current_app = "b" * 40
    old_config = "c" * 40
    current_config = "d" * 40
    current_id = "e" * 64
    old_id = "f" * 64

    def candidate_and_finding(self):
        candidate = {"repository": self.repo, "application_sha": self.current_app,
                     "configuration_sha": self.current_config}
        old_candidate = {"repository": self.repo, "application_sha": self.old_app,
                         "configuration_sha": self.old_config}
        finding = {"finding_id": "inline:91:701", "candidate_id": self.old_id,
                   "scope": "full", "source_sha": self.old_app,
                   "path": "pkg/target.go", "line": 2,
                   "body": "target returns an incorrect result"}
        return candidate, old_candidate, finding

    def test_changed_code_and_matching_test_do_not_synthesize_an_owner_receipt(self):
        candidate, old_candidate, finding = self.candidate_and_finding()
        current_tree = ("4" * 40, {
            "pkg/target.go": {"mode": "100644", "blob_sha": "5" * 40},
            "pkg/target_test.go": {"mode": "100644", "blob_sha": "6" * 40},
        })
        config_tree = ("7" * 40, {})
        trees = {self.current_app: current_tree, self.current_config: config_tree}
        # The new test exercises one branch of target(), but does not establish
        # that this particular carried finding was fixed.
        old_product = "func target(x int) int {\n\tif x == 0 { return 0 }\n\treturn 1\n}\n"
        current_product = "func target(x int) int {\n\tif x < 0 { return 0 }\n\treturn 1\n}\n"
        old_test = "func TestTarget(t *testing.T) {\n\tif target(0) != 0 { t.Fatal(\"old\") }\n}\n"
        current_test = "func TestTarget(t *testing.T) {\n\tif target(0) != 0 { t.Fatal(\"still passes\") }\n}\n"
        self.assertIn("if x == 0", old_product)
        self.assertIn("if x < 0", current_product)
        self.assertIn("target(0)", old_test)
        self.assertIn("target(0)", current_test)
        self.assertNotIn("target(-1)", current_test)
        findings = [finding]
        unrelated_receipt = {"review:90:999": {
            "candidate_id": self.old_id, "source_sha": self.old_app,
            "status": "fixed", "evidence": "A different finding has an owner receipt.",
        }}
        posted = []

        class Core:
            @staticmethod
            def candidate_identity(_candidate):
                return FindingDispositionReceiptTests.current_id

        def post(*args):
            posted.append(args)

        with (patch.object(release, "lifecycle_module", return_value=Core),
              patch.object(release, "native_review_tree", side_effect=lambda _repo, sha: trees[sha]),
              patch.object(release, "content", side_effect=AssertionError(
                  "A candidate code/test co-change is not a disposition")) as source_read,
              patch.object(release, "_post_finding_dispositions", side_effect=post)):
            release.create_review_finding_dispositions(
                self.repo, 91, candidate, findings,
                {self.old_id: {"candidate": old_candidate}}, unrelated_receipt, "owner-token")
        self.assertEqual(posted, [])
        source_read.assert_not_called()
        self.assertEqual(findings, [finding])

    def test_existing_owner_receipt_carries_forward_when_its_blob_is_unchanged(self):
        candidate, old_candidate, finding = self.candidate_and_finding()
        current_tree = ("4" * 40, {
            "pkg/target.go": {"mode": "100644", "blob_sha": "5" * 40},
        })
        config_tree = ("7" * 40, {})
        disposition_tree = ("8" * 40, {
            "pkg/target.go": {"mode": "100644", "blob_sha": "5" * 40},
        })
        trees = {self.current_app: current_tree, self.current_config: config_tree,
                 "9" * 40: disposition_tree}
        prior = {finding["finding_id"]: {
            "candidate_id": self.old_id, "source_sha": "9" * 40,
            "status": "fixed", "evidence": "The owner receipt names the exact changed function and regression.",
        }}
        posted = []

        class Core:
            @staticmethod
            def candidate_identity(_candidate):
                return FindingDispositionReceiptTests.current_id

        with (patch.object(release, "lifecycle_module", return_value=Core),
              patch.object(release, "native_review_tree", side_effect=lambda _repo, sha: trees[sha]),
              patch.object(release, "_post_finding_dispositions",
                           side_effect=lambda *args: posted.append(args))):
            release.create_review_finding_dispositions(
                self.repo, 91, candidate, [finding],
                {self.old_id: {"candidate": old_candidate}}, prior, "owner-token")
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0][2], self.current_id)
        self.assertEqual(posted[0][3], self.current_app)
        carried = posted[0][4][0]
        self.assertEqual(carried["finding_id"], finding["finding_id"])
        self.assertEqual(carried["status"], "fixed")
        self.assertIn("owner receipt", carried["evidence"])

    def test_stale_owner_receipt_does_not_clear_a_changed_affected_blob(self):
        candidate, old_candidate, finding = self.candidate_and_finding()
        current_tree = ("4" * 40, {
            "pkg/target.go": {"mode": "100644", "blob_sha": "5" * 40},
        })
        config_tree = ("7" * 40, {})
        stale_receipt_tree = ("8" * 40, {
            "pkg/target.go": {"mode": "100644", "blob_sha": "2" * 40},
        })
        trees = {self.current_app: current_tree, self.current_config: config_tree,
                 "9" * 40: stale_receipt_tree}
        prior = {finding["finding_id"]: {
            "candidate_id": self.old_id, "source_sha": "9" * 40,
            "status": "fixed", "evidence": "Earlier owner receipt for the previous blob.",
        }}
        findings = [finding]
        posted = []

        class Core:
            @staticmethod
            def candidate_identity(_candidate):
                return FindingDispositionReceiptTests.current_id

        with (patch.object(release, "lifecycle_module", return_value=Core),
              patch.object(release, "native_review_tree", side_effect=lambda _repo, sha: trees[sha]),
              patch.object(release, "_post_finding_dispositions",
                           side_effect=lambda *args: posted.append(args))):
            release.create_review_finding_dispositions(
                self.repo, 91, candidate, findings,
                {self.old_id: {"candidate": old_candidate}}, prior, "owner-token")
        self.assertEqual(posted, [])
        self.assertEqual(findings, [finding])


class GitHubContentsBase64Tests(unittest.TestCase):
    def test_line_wrapped_native_contents_are_decoded(self):
        raw = b"source bytes\n"
        encoded = base64.b64encode(raw).decode("ascii")
        wrapped = encoded[:8] + "\r\n" + encoded[8:]
        with patch.object(release, "api", return_value={
                "type": "file", "encoding": "base64", "content": wrapped,
                "size": len(raw),
                "sha": hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()}):
            self.assertEqual(release.content("owner/repo", "path", "sha"), b"source bytes\n")

    def test_invalid_base64_still_fails_closed(self):
        raw = b"source bytes\n"
        with patch.object(release, "api", return_value={
                "type": "file", "encoding": "base64", "content": "%%%",
                "size": len(raw),
                "sha": hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()}):
            with self.assertRaisesRegex(ValueError, "invalid file content"):
                release.content("owner/repo", "path", "sha")

    def test_native_content_requires_exact_regular_blob_size_and_sha(self):
        raw = b"source bytes\n"
        response = {
            "type": "file", "encoding": "base64",
            "content": base64.b64encode(raw).decode("ascii"), "size": len(raw),
            "sha": hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest(),
        }
        for field, value in (("size", len(raw) + 1), ("sha", "0" * 40)):
            with self.subTest(field=field), patch.object(
                    release, "api", return_value=dict(response, **{field: value})), \
                    self.assertRaisesRegex(ValueError, "size or regular blob SHA"):
                release.content("owner/repo", "path", "sha")


class ExplicitMachineFindingDispositionTests(unittest.TestCase):
    repo = "owner/osconfig"
    code = release.PREFIX + "release.py"
    test = release.PREFIX + "tests/test_release.py"

    def fixture(self, status="fixed", empty_diff=False):
        seed, head = "c" * 40, "e" * 40
        candidate = {"application_sha": "a" * 40, "configuration_sha": "b" * 40}
        manifest = {"candidate": candidate, "candidateIdentity": "f" * 64,
                    "candidatePr": 11, "proposalPr": 4, "proposalHeadSha": head, "configSha": seed}
        state = {"head": head, "seed": seed, "number": 4}
        finding = {"finding_id": "inline:1:2", "candidate_id": "f" * 64,
                   "scope": "delta", "source": "inline",
                   "source_sha": candidate["configuration_sha"], "native_id": 2,
                   "body": "The reported inventory state is lost.",
                   "path": "agentendpoint/inventory.go", "line": 42,
                   "severity": "P1", "source_tree_sha": "d" * 40}
        pair = {"state": "findings", "complete": True, "findings": [finding],
                "observed_findings": [finding]}
        code_data = "def repaired(): return good"
        test_data = "def test_repaired(): assert fixed"
        code_before = code_data if empty_diff else "def repaired(): return bad"
        test_before = test_data if empty_diff else "def test_repaired(): assert broken"
        code_diff = b"" if empty_diff else b"+return good\n"
        test_diff = b"" if empty_diff else b"+def test_repaired():\n+    assert fixed\n"
        records = {self.code: {"before": code_before, "data": code_data, "diff": code_diff,
                              "diff_sha256": hashlib.sha256(code_diff).hexdigest()},
                   self.test: {"before": test_before, "data": test_data, "diff": test_diff,
                              "diff_sha256": hashlib.sha256(test_diff).hexdigest()}}
        evidence = (f"code location `{self.code}` at `return good`; code diff SHA-256 "
                    f"`{records[self.code]['diff_sha256']}`; regression path `{self.test}`; "
                    f"regression diff SHA-256 `{records[self.test]['diff_sha256']}`; "
                    "regression case `test_repaired`; regression location `assert fixed`; "
                    "explanation `the old path loses state and the regression asserts retained state`;")
        report = {"schema": 1, "source_sha": head,
                  "findings": [{"finding_id": finding["finding_id"], "status": status, "evidence": evidence}]}
        comments = [
            {"id": 1, "user": {"login": "owner", "type": "User"},
             "created_at": "2026-10-17T12:00:00Z", "updated_at": "2026-10-17T12:00:00Z",
             "body": "<!-- osconfig-policy-fix:v1 " + seed + " 1792238400 -->"},
            {"id": 2, "user": {"login": release.BOT, "type": "Bot", "id": 100},
             "performed_via_github_app": {"slug": release.APP, "id": 200},
             "created_at": "2026-10-17T12:01:00Z", "updated_at": "2026-10-17T12:01:00Z",
             "body": "<!-- fork-review-disposition:v1 " + json.dumps(report) + " -->"}]
        pull = {"state": "open", "head": {"sha": head, "repo": {"full_name": self.repo}},
                "base": {"sha": seed, "repo": {"full_name": self.repo}}}
        tree = {self.code: {"mode": "100644", "blob_sha": "1" * 40},
                self.test: {"mode": "100644", "blob_sha": "2" * 40}}
        return manifest, state, pair, records, comments, pull, tree

    def call(self, fixture, *, full_complete=True, delta_complete=True, tree_mismatch=False,
             checked_pair=None, reject_post=False):
        manifest, state, pair, records, comments, pull, tree = fixture
        def api(route, **kwargs):
            if "/pulls/" in route:
                return pull
            if "/compare/" in route:
                return {"status": "ahead", "merge_base_commit": {"sha": state["seed"]}}
            raise AssertionError("Unexpected native endpoint " + route)
        def native_tree(repo, revision):
            result = {path: dict(entry) for path, entry in tree.items()}
            if tree_mismatch and revision == manifest["candidate"]["configuration_sha"]:
                result[self.code]["blob_sha"] = "9" * 40
            return "d" * 40, result
        full, delta = {"complete": full_complete}, {"complete": delta_complete}
        ready = {"state": "ready", "complete": True, "findings": []}
        checked_pair = pair if checked_pair is None else checked_pair
        with patch.object(release, "api", side_effect=api), \
                patch.object(release, "pages", return_value=comments), \
                patch.object(release, "policy_identity", return_value=state), \
                patch.object(release, "native_review_tree", side_effect=native_tree), \
                patch.object(release, "_proposal_source_records", return_value=records) as sources, \
                patch.object(release, "_post_finding_dispositions",
                             side_effect=AssertionError("unexpected owner POST") if reject_post else None) as post, \
                patch.object(release, "review_pair_status", side_effect=[(full, delta, checked_pair),
                                                                         (full, delta, ready)]):
            result = release.complete_machine_finding_dispositions(
                self.repo, manifest, full, delta, pair, "owner-token")
        return result, post, sources

    def test_recheck_compares_complete_unresolved_and_observed_native_findings(self):
        mutations = {"body": "edited finding", "path": "another/path.go",
                     "scope": "full", "source": "formal-review",
                     "source_sha": "9" * 40, "native_id": 999}
        for collection in ("findings", "observed_findings"):
            for field, value in mutations.items():
                with self.subTest(collection=collection, field=field):
                    fixture = self.fixture()
                    checked_pair = json.loads(json.dumps(fixture[2]))
                    checked_pair[collection][0][field] = value
                    with self.assertRaisesRegex(ValueError, "changed before disposition"):
                        self.call(fixture, checked_pair=checked_pair, reject_post=True)

    def test_explicit_exact_report_posts_the_complete_configuration_bound_batch(self):
        fixture = self.fixture()
        result, post, sources = self.call(fixture)
        self.assertEqual(result[2]["state"], "ready")
        post.assert_called_once()
        self.assertEqual(post.call_args.args[:4], (self.repo, 11, "f" * 64, "b" * 40))
        self.assertEqual(post.call_args.args[4][0]["finding_id"], "inline:1:2")
        sources.assert_called_once_with(self.repo, "c" * 40, "e" * 40, {self.code, self.test})

    def test_unchanged_explicit_disproof_needs_no_fake_source_changes(self):
        result, post, _ = self.call(self.fixture(status="disproved", empty_diff=True))
        self.assertEqual(result[2]["state"], "ready")
        self.assertEqual(post.call_args.args[4][0]["status"], "disproved")

    def test_both_fresh_scopes_are_required_before_any_source_or_owner_operation(self):
        for full, delta in ((False, True), (True, False)):
            with self.subTest(full=full, delta=delta):
                result, post, sources = self.call(self.fixture(), full_complete=full, delta_complete=delta)
                self.assertEqual(result[2]["state"], "findings")
                post.assert_not_called()
                sources.assert_not_called()

    def test_absent_report_keeps_findings_for_the_existing_repair_task(self):
        fixture = self.fixture()
        fixture[4].pop()
        result, post, sources = self.call(fixture)
        self.assertEqual(result[2]["state"], "findings")
        post.assert_not_called()
        sources.assert_not_called()

    def test_partial_scope_post_retries_only_the_remaining_findings(self):
        fixture = self.fixture()
        manifest, state, _pair, records, comments, pull, tree = fixture
        delta_finding = dict(fixture[2]["findings"][0])
        full_finding = dict(delta_finding, finding_id="inline:1:3", scope="full",
                            source_sha=manifest["candidate"]["application_sha"], native_id=3,
                            body="The full review also reports lost state.", line=43)
        pair_before = {"state": "findings", "complete": True,
                       "findings": [full_finding, delta_finding],
                       "observed_findings": [full_finding, delta_finding]}
        pair_after_full = {"state": "findings", "complete": True,
                           "findings": [delta_finding],
                           "observed_findings": [full_finding, delta_finding],
                           "dispositions_applied": [full_finding["finding_id"]]}
        ready = {"state": "ready", "complete": True, "findings": [],
                 "observed_findings": [full_finding, delta_finding]}
        marker_prefix = "<!-- fork-review-disposition:v1 "
        report = json.loads(comments[-1]["body"][len(marker_prefix):-4])
        report["findings"].append(dict(report["findings"][0], finding_id=full_finding["finding_id"]))
        comments[-1]["body"] = marker_prefix + json.dumps(report) + " -->"
        full_report_item = report["findings"][-1]
        manifest["findingDispositions"] = [{
            **full_report_item, "candidate_id": manifest["candidateIdentity"],
            "source_sha": manifest["candidate"]["application_sha"],
            "native_comment": {"id": 12, "created_at": "2026-10-17T12:03:00Z",
                               "updated_at": "2026-10-17T12:03:00Z",
                               "user": {"login": "owner", "type": "User"}},
        }]

        def api(route, **kwargs):
            if "/pulls/" in route:
                return pull
            if "/compare/" in route:
                return {"status": "ahead", "merge_base_commit": {"sha": state["seed"]}}
            raise AssertionError("Unexpected native endpoint " + route)

        def native_tree(repo, revision):
            return "d" * 40, {path: dict(entry) for path, entry in tree.items()}

        full, delta = {"complete": True}, {"complete": True}
        results = [(full, delta, pair_before), (full, delta, pair_after_full),
                   (full, delta, ready)]
        posted = []

        def post(repo, pull_number, candidate_id, source_sha, findings, token):
            posted.append((source_sha, [item["finding_id"] for item in findings]))
            if len(posted) == 2:
                raise RuntimeError("simulated delta-scope POST failure")

        with patch.object(release, "api", side_effect=api), \
                patch.object(release, "pages", return_value=comments), \
                patch.object(release, "policy_identity", return_value=state), \
                patch.object(release, "native_review_tree", side_effect=native_tree), \
                patch.object(release, "_proposal_source_records", return_value=records), \
                patch.object(release, "_post_finding_dispositions", side_effect=post), \
                patch.object(release, "review_pair_status", side_effect=results):
            with self.assertRaisesRegex(RuntimeError, "delta-scope"):
                release.complete_machine_finding_dispositions(
                    self.repo, manifest, full, delta, pair_before, "owner-token")
            native_disposition = manifest["findingDispositions"][0]
            for field, wrong_value in (("source_sha", "9" * 40), ("status", "disproved"),
                                       ("evidence", "mismatched owner evidence")):
                with self.subTest(field=field):
                    original = native_disposition[field]
                    native_disposition[field] = wrong_value
                    with self.assertRaisesRegex(ValueError, "disagrees with its exact native owner disposition"):
                        release.complete_machine_finding_dispositions(
                            self.repo, manifest, full, delta, pair_after_full, "owner-token")
                    native_disposition[field] = original
            result = release.complete_machine_finding_dispositions(
                self.repo, manifest, full, delta, pair_after_full, "owner-token")
        self.assertEqual(result[2]["state"], "ready")
        self.assertEqual(posted, [("a" * 40, [full_finding["finding_id"]]),
                                  ("b" * 40, [delta_finding["finding_id"]]),
                                  ("b" * 40, [delta_finding["finding_id"]])])

    def test_new_same_second_owner_request_retires_old_malformed_report(self):
        fixture = self.fixture()
        manifest, state, pair, records, comments, pull, tree = fixture
        old_report = comments[-1]
        old_report["body"] = "<!-- fork-review-disposition:v1 {malformed old report -->"
        old_report["updated_at"] = "2026-10-17T12:05:00Z"
        comments.append({"id": 3, "user": {"login": "owner", "type": "User"},
                         "created_at": "2026-10-17T12:01:00Z",
                         "updated_at": "2026-10-17T12:01:00Z",
                         "body": "<!-- osconfig-policy-fix:v1 " + state["seed"] + " 1792238460 -->"})
        report = {"schema": 1, "source_sha": state["head"],
                  "findings": [{"finding_id": pair["findings"][0]["finding_id"],
                                "status": "fixed",
                                "evidence": (f"code location `{self.code}` at `return good`; "
                                             f"code diff SHA-256 `{records[self.code]['diff_sha256']}`; "
                                             f"regression path `{self.test}`; "
                                             f"regression diff SHA-256 `{records[self.test]['diff_sha256']}`; "
                                             "regression case `test_repaired`; "
                                             "regression location `assert fixed`; "
                                             "explanation `the exact regression now covers retained state`;")}]}
        comments.append({"id": 4, "user": {"login": release.BOT, "type": "Bot", "id": 100},
                         "performed_via_github_app": {"slug": release.APP, "id": 200},
                         "created_at": "2026-10-17T12:02:00Z",
                         "updated_at": "2026-10-17T12:02:00Z",
                         "body": "<!-- fork-review-disposition:v1 " + json.dumps(report) + " -->"})
        result, post, _sources = self.call(fixture)
        self.assertEqual(result[2]["state"], "ready")
        post.assert_called_once()

    def test_policy_request_head_may_be_an_ancestor_of_the_repair_commit(self):
        fixture = self.fixture()
        result, post, _sources = self.call(fixture)
        self.assertEqual(result[2]["state"], "ready")
        post.assert_called_once()

    def test_policy_request_that_is_not_an_ancestor_of_the_repair_commit_is_rejected(self):
        fixture = self.fixture()
        fixture[4][0]["body"] = "<!-- osconfig-policy-fix:v1 " + "9" * 40 + " 1792238400 -->"
        with self.assertRaisesRegex(ValueError, "not an ancestor of its native PR head"):
            self.call(fixture)

    def test_current_wrong_source_proposal_is_rejected(self):
        fixture = self.fixture()
        comments = fixture[4]
        marker_prefix = "<!-- fork-review-disposition:v1 "
        report = json.loads(comments[-1]["body"][len(marker_prefix):-4])
        report["source_sha"] = "9" * 40
        comments[-1]["body"] = marker_prefix + json.dumps(report) + " -->"
        with self.assertRaisesRegex(ValueError, "different source SHA"):
            self.call(fixture)

    def test_conflicting_current_reports_are_not_silently_selected(self):
        fixture = self.fixture()
        comments = fixture[4]
        duplicate = dict(comments[-1])
        duplicate["id"] = 3
        duplicate["created_at"] = "2026-10-17T12:02:00Z"
        duplicate["updated_at"] = duplicate["created_at"]
        comments.append(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicated"):
            self.call(fixture)

    def test_application_patch_evidence_binds_added_go_test_hunk(self):
        manifest, _state, pair, _records, _comments, _pull, _tree = self.fixture()
        head, upstream = "e" * 40, "d" * 40
        application = manifest["candidate"]["application_sha"]
        manifest.pop("proposalPr")
        manifest.update({"upstreamCommit": upstream, "candidateBranch": "review/application"})
        finding = {"finding_id": "inline:1:2", "candidate_id": manifest["candidateIdentity"],
                   "scope": "full", "source": "inline", "source_sha": application,
                   "native_id": 2, "body": "The reported inventory state is lost.",
                   "path": "agentendpoint/inventory.go", "line": 42,
                   "severity": "P1", "source_tree_sha": "d" * 40}
        pair["findings"] = [finding]
        pair["observed_findings"] = [finding]
        path = release.PATCH_REL
        patch_source = (
            "diff --git a/agentendpoint/inventory.go b/agentendpoint/inventory.go\n"
            "index 1111111..2222222 100644\n"
            "--- a/agentendpoint/inventory.go\n"
            "+++ b/agentendpoint/inventory.go\n"
            "@@ -1,0 +2 @@\n"
            "+func inventoryState() string { return \"retained\" }\n"
            "diff --git a/agentendpoint/inventory_test.go b/agentendpoint/inventory_test.go\n"
            "index 3333333..4444444 100644\n"
            "--- a/agentendpoint/inventory_test.go\n"
            "+++ b/agentendpoint/inventory_test.go\n"
            "@@ -1,0 +2,5 @@\n"
            "+func TestInventoryStateRetained(t *testing.T) {\n"
            "+    if inventoryState() != \"retained\" {\n"
            "+        t.Fatal(\"state lost\")\n"
            "+    }\n"
            "+}\n")
        diff = b"exact source diff bytes"
        records = {path: {"before": "", "data": patch_source, "diff": diff,
                          "diff_sha256": hashlib.sha256(diff).hexdigest()}}
        evidence = (f"code location `{path}` at `inventoryState() string`; code diff SHA-256 "
                    f"`{records[path]['diff_sha256']}`; regression path `{path}`; regression diff SHA-256 "
                    f"`{records[path]['diff_sha256']}`; regression case `TestInventoryStateRetained`; "
                    "regression location `t.Fatal(\"state lost\")`; "
                    "explanation `the added source state is covered by its exact Go regression hunk`;")
        request = {"id": 1, "user": {"login": "owner", "type": "User"},
                   "created_at": "2026-10-17T12:00:00Z", "updated_at": "2026-10-17T12:00:00Z",
                   "body": f"<!-- osconfig-fix-window:v1 {application} 1792238400 -->"}
        report = {"schema": 1, "source_sha": head,
                  "findings": [{"finding_id": finding["finding_id"],
                                "status": "fixed", "evidence": evidence}]}
        proposal = {"id": 2, "user": {"login": release.BOT, "type": "Bot", "id": 100},
                    "performed_via_github_app": {"slug": release.APP, "id": 200},
                    "created_at": "2026-10-17T12:01:00Z", "updated_at": "2026-10-17T12:01:00Z",
                    "body": "<!-- fork-review-disposition:v1 " + json.dumps(report) + " -->"}
        pull = {"state": "open",
                "head": {"sha": head, "ref": "review/application", "repo": {"full_name": self.repo}},
                "base": {"sha": upstream, "ref": f"review-base/{upstream}",
                         "repo": {"full_name": self.repo}}}
        tree = {path: {"mode": "100644", "blob_sha": "1" * 40}}

        def api(route, **kwargs):
            if "/pulls/" in route:
                return pull
            if f"/compare/{head}...{application}" in route:
                return {"status": "ahead", "merge_base_commit": {"sha": head}}
            if f"/compare/{application}...{head}" in route:
                return {"status": "ahead", "merge_base_commit": {"sha": application}}
            raise AssertionError("Unexpected native endpoint " + route)

        full, delta = {"complete": True}, {"complete": True}
        ready = {"state": "ready", "complete": True, "findings": [],
                 "observed_findings": [finding]}
        with patch.object(release, "api", side_effect=api), \
                patch.object(release, "pages", return_value=[request, proposal]), \
                patch.object(release, "native_review_tree", return_value=("f" * 40, tree)), \
                patch.object(release, "_proposal_source_records", return_value=records), \
                patch.object(release, "_post_finding_dispositions") as post, \
                patch.object(release, "review_pair_status", side_effect=[(full, delta, pair),
                                                                         (full, delta, ready)]):
            result = release.complete_machine_finding_dispositions(
                self.repo, manifest, full, delta, pair, "owner-token")
        self.assertEqual(result[2]["state"], "ready")
        post.assert_called_once()
        self.assertEqual(post.call_args.args[3], application)

    def test_edited_report_wrong_hash_missing_ids_and_changed_adoption_blobs_refuse(self):
        for kind in ("edited", "wrong-hash", "missing-id", "tree", "fake-fixed"):
            with self.subTest(kind=kind):
                fixture = self.fixture(empty_diff=kind == "fake-fixed")
                report = fixture[4][-1]
                if kind == "edited":
                    report["updated_at"] = "2026-10-17T12:02:00Z"
                elif kind == "wrong-hash":
                    fixture[3][self.code]["diff_sha256"] = "0" * 64
                elif kind == "missing-id":
                    report["body"] = report["body"].replace("inline:1:2", "inline:1:3")
                with self.assertRaises(ValueError):
                    self.call(fixture, tree_mismatch=kind == "tree")


class DeltaSnapshotProductModeTests(unittest.TestCase):
    baseline = "a" * 40
    application_sha = "b" * 40
    config_sha = "c" * 40
    delta_tree = "d" * 40
    delta_sha = "e" * 40

    def product_trees(self, *, invalid=None):
        config, application = {}, {}
        for index, path in enumerate(release.FULL_PRODUCT_PATHS, start=1):
            config[path] = {
                "mode": ("100755" if Path(path).name in {"build-rpm.sh", "prepare-source.sh"}
                         else "100644"),
                "blob_sha": f"{index:040x}",
            }
            application[path] = {"mode": "100644", "blob_sha": f"{index + 100:040x}"}
        if invalid:
            side, kind, path = invalid
            if kind == "missing":
                (config if side == "config" else application).pop(path)
            elif kind == "mode":
                (config if side == "config" else application)[path]["mode"] = "120000"
        return config, application

    def run_delta(self, *, invalid=None):
        config_tree, application_tree = self.product_trees(invalid=invalid)
        config_path = Path("/source-config")
        commands = []

        def ls_tree(tree):
            return "\n".join(
                f"{entry['mode']} blob {entry['blob_sha']}\t{path}"
                for path, entry in sorted(tree.items()))

        def fake_run(*args, cwd=None, env=None, input=None):
            commands.append(args)
            if args[:3] == ("git", "rev-parse", "FETCH_HEAD"):
                return self.baseline
            if args[:2] == ("git", "ls-tree"):
                tree = config_tree if args[4] == self.config_sha else application_tree
                return ls_tree(tree)
            if args[:2] == ("git", "write-tree"):
                return self.delta_tree
            if args[:2] == ("git", "commit-tree"):
                return self.delta_sha
            return ""

        with patch.object(release, "run", side_effect=fake_run), \
             patch.object(release, "ensure_review_base"), \
             patch.object(release, "downstream_context_paths", return_value=[]), \
             patch.object(release, "copy_checked_out_review_files", return_value=[]):
            result = release.create_delta_snapshot(
                Path("/application"), baseline_config=self.baseline,
                application_sha=self.application_sha,
                source_root=config_path, source_config_sha=self.config_sha,
                repo="warelik/osconfig")
        return result, commands, config_tree, application_tree

    def test_delta_uses_configuration_modes_and_exact_application_blobs(self):
        (delta_sha, _), commands, config_tree, application_tree = self.run_delta()
        cacheinfo = {args[3] for args in commands
                     if args[:3] == ("git", "update-index", "--cacheinfo")}
        expected = {
            f"{config_tree[path]['mode']},{application_tree[path]['blob_sha']},{path}"
            for path in release.FULL_PRODUCT_PATHS
        }
        self.assertEqual(cacheinfo, expected)
        self.assertIn(("git", "checkout-index", "--force", "--", *release.FULL_PRODUCT_PATHS),
                      commands)
        self.assertEqual(delta_sha, self.delta_sha)

    def test_incomplete_or_nonregular_product_maps_fail_before_delta_checkout(self):
        cases = (
            ("missing-config", "config", "missing"),
            ("nonregular-config", "config", "mode"),
            ("missing-application", "application", "missing"),
            ("nonregular-application", "application", "mode"),
        )
        for label, side, kind in cases:
            with self.subTest(case=label):
                invalid_path = release.FULL_PRODUCT_PATHS[0]
                invalid = (side, kind, invalid_path)
                config_path, application_path = Path("/source-config"), Path("/application")
                config_tree, application_tree = self.product_trees(invalid=invalid)
                commands = []

                def fake_run(*args, cwd=None, env=None, input=None):
                    commands.append(args)
                    if args[:3] == ("git", "rev-parse", "FETCH_HEAD"):
                        return self.baseline
                    if args[:2] == ("git", "ls-tree"):
                        tree = config_tree if args[4] == self.config_sha else application_tree
                        return "\n".join(
                            f"{entry['mode']} blob {entry['blob_sha']}\t{path}"
                            for path, entry in sorted(tree.items()))
                    return ""

                with patch.object(release, "run", side_effect=fake_run), \
                     patch.object(release, "ensure_review_base") as ensure_base:
                    expected = "unsupported mode or blob" if kind == "mode" else "incomplete"
                    with self.assertRaisesRegex(ValueError, expected):
                        release.create_delta_snapshot(
                            application_path, baseline_config=self.baseline,
                            application_sha=self.application_sha,
                            source_root=config_path, source_config_sha=self.config_sha,
                            repo="warelik/osconfig")
                ensure_base.assert_not_called()
                self.assertFalse(any(args[:3] == ("git", "checkout", "-B")
                                     for args in commands))


class FailedJobEvidenceTests(unittest.TestCase):
    repo = "warelik/osconfig"
    run_id = "4294967296"

    def test_current_run_completed_failure_uses_direct_job_log_endpoint(self):
        class Response:
            def __init__(self, content):
                self.content = content

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                chunk, self.content = self.content[:size], self.content[size:]
                return chunk

        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response(payload)

        jobs = [{"id": 91, "run_id": int(self.run_id), "name": "build-rpm", "status": "completed",
                 "conclusion": "failure", "html_url": f"https://github.com/{self.repo}/actions/runs/{self.run_id}/jobs/91"}]
        payload = ("\x1b[31mfailed\x1b[0m\nAuthorization: Bearer ghp_" + "x" * 40 + "\n").encode()
        opener = Opener()
        with patch.object(release, "pages", return_value=jobs), \
             patch.object(release, "build_opener", return_value=opener) as build, \
             patch.dict(os.environ, {"GH_TOKEN": "test-token", "GITHUB_TOKEN": ""}):
            evidence = release.failed_job_evidence(self.repo, self.run_id)
        request = opener.request
        self.assertIsInstance(build.call_args.args[0], release.GitHubJobLogRedirect)
        self.assertEqual(request.full_url,
                         f"https://api.github.com/repos/{self.repo}/actions/jobs/91/logs")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertEqual(opener.timeout, 45)
        self.assertIn("Failed job: build-rpm", evidence)
        self.assertIn("failed", evidence)
        self.assertNotIn("\x1b", evidence)
        self.assertNotIn("ghp_", evidence)
        self.assertIn(f"https://github.com/{self.repo}/actions/runs/{self.run_id}", evidence)

    def test_unavailable_job_log_keeps_run_and_job_links_with_reason(self):
        jobs = [{"id": 92, "name": "publish", "status": "completed", "conclusion": "failure"}]
        with patch.object(release, "pages", return_value=jobs), \
             patch.object(release, "completed_job_log", side_effect=RuntimeError("Resource not accessible by integration")):
            evidence = release.failed_job_evidence(self.repo, self.run_id)
        self.assertIn("Completed job log unavailable", evidence)
        self.assertIn("Resource not accessible by integration", evidence)
        self.assertIn(f"{self.repo}/actions/runs/{self.run_id}/jobs/92", evidence)

    def test_active_run_without_completed_failure_has_explicit_fallback(self):
        jobs = [{"id": 93, "name": "publish", "status": "in_progress", "conclusion": None}]
        with patch.object(release, "pages", return_value=jobs), \
             patch.object(release, "completed_job_log") as fetch:
            evidence = release.failed_job_evidence(self.repo, self.run_id)
        fetch.assert_not_called()
        self.assertIn("No completed failed jobs are available yet", evidence)
        self.assertIn("publish: status=in_progress", evidence)

    def test_job_list_api_failure_is_not_silently_discarded(self):
        with patch.object(release, "pages", side_effect=RuntimeError("HTTP 403")):
            evidence = release.failed_job_evidence(self.repo, self.run_id)
        self.assertIn("Completed failed-job list unavailable: HTTP 403", evidence)
        self.assertIn(f"https://github.com/{self.repo}/actions/runs/{self.run_id}", evidence)

    def test_job_log_timeout_has_explicit_job_fallback(self):
        jobs = [{"id": 94, "name": "sign", "status": "completed", "conclusion": "failure"}]
        with patch.object(release, "pages", return_value=jobs), \
             patch.object(release, "build_opener", side_effect=TimeoutError("network timeout")):
            evidence = release.failed_job_evidence(self.repo, self.run_id)
        self.assertIn("Completed job log unavailable: GitHub job-log request exceeded 45 seconds", evidence)
        self.assertIn(f"{self.repo}/actions/runs/{self.run_id}/jobs/94", evidence)


    def test_external_log_redirect_drops_the_github_api_token(self):
        handler = release.GitHubJobLogRedirect()
        request = release.Request(
            "https://api.github.com/repos/warelik/osconfig/actions/jobs/95/logs",
            headers={"Authorization": "Bearer test-token"},
        )
        signed = handler.redirect_request(
            request, None, 302, "Found", {}, "https://logs.example.invalid/signed?sig=temporary"
        )
        self.assertIsNotNone(signed)
        self.assertIsNone(signed.get_header("Authorization"))
        same_origin = handler.redirect_request(
            request, None, 302, "Found", {}, "https://api.github.com/repos/warelik/osconfig/logs"
        )
        self.assertEqual(same_origin.get_header("Authorization"), "Bearer test-token")
        self.assertIsNone(handler.redirect_request(
            request, None, 302, "Found", {}, "http://logs.example.invalid/plain"
        ))


class FinalRetryGrantPolicyRepairTests(unittest.TestCase):
    repo = "warelik/osconfig"
    config = "a" * 40

    def evidence(self, reason, job="final-guard"):
        return (f"Workflow run: https://github.com/{self.repo}/actions/runs/123\n\n"
                f"Failed job: {job} (https://github.com/{self.repo}/actions/runs/123/jobs/456)\n"
                f"OS Config package stopped: {reason}")

    def test_only_the_exact_final_guard_retry_grant_refusals_are_classified(self):
        for reason in release.FINAL_RETRY_GRANT_REASONS:
            with self.subTest(reason=reason):
                self.assertTrue(release.final_retry_grant_failure(self.evidence(reason)))
        self.assertFalse(release.final_retry_grant_failure(
            self.evidence(next(iter(release.FINAL_RETRY_GRANT_REASONS)), job="build-rpm")))
        self.assertFalse(release.final_retry_grant_failure(
            self.evidence("The latest stopped heavy failure needs one unique exact-candidate owner grant later")))
        timestamped = self.evidence(next(iter(release.FINAL_RETRY_GRANT_REASONS))).replace(
            "OS Config package stopped:",
            "2026-10-21T09:33:14.1234567Z OS Config package stopped:")
        self.assertTrue(release.final_retry_grant_failure(timestamped))
        duplicate = self.evidence(next(iter(release.FINAL_RETRY_GRANT_REASONS)))
        self.assertFalse(release.final_retry_grant_failure(
            duplicate + "\n\nFailed job: publish (https://github.com/example/run)\nOther failure"))

    def test_expected_owner_grant_wait_does_not_open_publisher_repair(self):
        evidence = self.evidence(next(iter(release.FINAL_RETRY_GRANT_REASONS)))
        with (patch.dict(os.environ, {"GITHUB_REPOSITORY": self.repo,
                                      "GITHUB_SHA": self.config}),
              patch.object(release, "api", return_value={"sha": self.config}),
              patch.object(release, "report_permission_blocker") as blocker,
              patch.object(release, "owner_token") as token,
              patch.object(release, "open_policy_pull") as opened,
              patch.object(release, "create_policy_pull") as created,
              patch.object(release, "request_policy_task") as task):
            release.request_policy_repair(evidence)
        blocker.assert_not_called()
        token.assert_not_called()
        opened.assert_not_called()
        created.assert_not_called()
        task.assert_not_called()


class PaginationAndApiDiagnosticsTests(unittest.TestCase):
    repo = "warelik/osconfig"

    def test_candidate_preflight_checks_late_open_policy_pull_requests(self):
        pulls = [{"head": {"ref": f"feature/{number}",
                           "repo": {"full_name": self.repo}}} for number in range(100)]
        pulls.append({"head": {"ref": "repair/osconfig-policy-example",
                                "repo": {"full_name": self.repo}}})
        with patch.object(release, "pages", return_value=pulls) as page_reader:
            self.assertTrue(release.active_policy_candidate_exists(self.repo))
        page_reader.assert_called_once_with(
            f"repos/{self.repo}/pulls?state=open&base={release.DEFAULT_BRANCH}")

    def test_native_pagination_fails_closed_at_its_page_bound(self):
        with patch.object(release, "MAX_API_PAGES", 2), \
                patch.object(release, "api", return_value=[{} for _ in range(100)]) as github_api:
            with self.assertRaisesRegex(ValueError, "pagination did not terminate"):
                release.pages(f"repos/{self.repo}/pulls?state=open")
        self.assertEqual(github_api.call_count, 2)

    def test_real_cli_reports_api_denial_without_the_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            secret = "ghp_" + "s" * 40
            gh = binary / "gh"
            gh.write_text("#!/bin/sh\nprintf '%s\\n' 'permission denied Authorization: Bearer " + secret + "' >&2\nexit 1\n")
            gh.chmod(0o700)
            settings = release.repository_settings()
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       GITHUB_REPOSITORY=settings["github_owner"] + "/" + settings["github_repo"],
                       GITHUB_SHA="a" * 40, OSCONFIG_RPM_SIGNING_FINGERPRINT=settings["signing_fingerprint"])
            result = subprocess.run([sys.executable, "-I", "-B", str(release.PATCH_DIR / "release.py"),
                                     "prepare", str(root / "candidate")], cwd=root, env=env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertIn("permission denied", result.stderr)
            self.assertNotIn(secret, result.stderr)

    def test_jobs_envelope_paginates_until_total_count(self):
        first = [{"id": number, "status": "completed", "conclusion": "failure"}
                 for number in range(100)]
        second = [{"id": 100, "status": "completed", "conclusion": "failure"}]
        with patch.object(release, "api", side_effect=[
            {"total_count": 101, "jobs": first},
            {"total_count": 101, "jobs": second},
        ]) as github_api:
            jobs = release.pages("repos/warelik/osconfig/actions/runs/1/jobs")
        self.assertEqual(len(jobs), 101)
        self.assertEqual(jobs[-1]["id"], 100)
        self.assertEqual(github_api.call_count, 2)

    def test_api_failure_keeps_bounded_sanitized_stderr(self):
        secret = "ghp_" + "x" * 40
        failure = subprocess.CalledProcessError(
            1, ["gh", "api"], stderr="useful denial " + secret + "&sig=signed-secret " + "z" * 10000)
        with patch.object(subprocess, "run", side_effect=failure), \
             self.assertRaises(subprocess.CalledProcessError) as raised:
            release.api("repos/warelik/osconfig/pulls", method="POST", data={"title": "x"})
        detail = raised.exception.stderr
        self.assertIn("earlier API error omitted", detail)
        self.assertNotIn(secret, detail)
        self.assertNotIn("signed-secret", detail)
        self.assertLessEqual(len(detail), release.API_ERROR_LIMIT + 32)


class PublisherRepairDeliveryTests(unittest.TestCase):
    def test_application_task_requires_verified_delivery_to_manifest_candidate(self):
        repo = "warelik/osconfig"
        number = 42
        candidate_sha = "b" * 40
        upstream = "c" * 40
        config = "d" * 40
        branch = "review/osconfig-exact-candidate"
        candidate = {
            "schema": 1, "repository": repo, "upstream_sha": upstream,
            "application_sha": candidate_sha, "configuration_sha": config,
            "patchset_sha256": "1" * 64, "recipe_sha256": "2" * 64,
            "platform": "fedora-44/x86_64",
        }
        candidate_id = release.frozen_candidate_identity(candidate)
        manifest = {
            "candidate": candidate,
            "candidateIdentity": candidate_id,
            "candidatePr": number,
            "candidateSha": candidate_sha,
            "candidateBranch": branch,
            "upstreamCommit": upstream,
            "configSha": config,
        }
        pull = {
            "number": number,
            "state": "open",
            "base": {
                "ref": f"review-base/{upstream}",
                "sha": upstream,
                "repo": {"full_name": repo},
            },
            "head": {
                "ref": branch,
                "sha": candidate_sha,
                "repo": {"full_name": repo},
            },
        }
        captured = []

        def fake_api(path, **kwargs):
            captured.append((path, kwargs))
            return pull if path == f"repos/{repo}/pulls/{number}" else None

        with tempfile.TemporaryDirectory(prefix="osconfig-application-repair-task-") as temporary:
            candidate_dir = Path(temporary)
            (candidate_dir / "candidate-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            with patch.object(release, "api", side_effect=fake_api), \
                 patch.object(release, "pages", return_value=[]), \
                 patch.object(release, "owner_token", return_value="fixture-token"), \
                 patch.dict(os.environ, {"GITHUB_REPOSITORY": repo}):
                release.request_fix(candidate_dir, "package build failed")

        comment = next(call for call in captured
                       if call[0] == f"repos/{repo}/issues/{number}/comments")
        body = comment[1]["data"]["body"]
        self.assertIn(f"`candidatePr` #{number}", body)
        self.assertIn(f"`candidateBranch` `{branch}`", body)
        self.assertIn("commit and push", body)
        self.assertIn(f"read back PR #{number} with the GitHub API", body)
        self.assertIn("`head.ref` is exactly", body)
        self.assertIn("`head.sha` equals the pushed commit SHA", body)
        self.assertIn("A local diff or commit is not delivery", body)
        self.assertIn("report the exact command and error and do not claim delivery", body)
        self.assertIn("Do not create another PR or force-push", body)
        self.assertIn("Do not change the local-only `check-upstream.sh` diagnostic", body)
        self.assertIn("fork-review-disposition:v1", body)
        self.assertIn(f"exact current `candidate_id` `{candidate_id}`", body)
        self.assertIn('"finding_id":"actual native finding ID"', body)
        self.assertIn('"status":"fixed or disproved"', body)
        self.assertIn('"evidence":"..."', body)
        self.assertIn("`source_sha`", body)
        self.assertIn("`application_sha` for full scope or `configuration_sha` for delta scope", body)
        self.assertIn("specific regression test path and test name/assertion", body)
        self.assertIn("Use the existing authorized native owner API; no human approval is needed", body)
        self.assertIn("leave that finding unresolved", body)

    def test_candidate_checkout_has_full_history_in_template_and_installed_workflow(self):
        yaml = release.yaml_module()
        proposed = os.environ.get("OSCONFIG_POLICY_CANDIDATE_WORKFLOW")
        paths = ([Path(proposed)] if proposed else
                 [release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml",
                  release.ROOT / ".github/workflows/google-osconfig-agent-inventory.yml"])
        for path in paths:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            steps = document["jobs"]["policy-check"]["steps"]
            checkout = next(step for step in steps
                            if step.get("with", {}).get("path") == "candidate")
            self.assertEqual(checkout["with"].get("fetch-depth"), 0, path)
            prepare = next(step for step in steps
                           if "release.py prepare-policy candidate" in step.get("run", ""))
            self.assertEqual(prepare["env"]["POLICY_HEAD_SHA"],
                             "${{ steps.identity.outputs.head }}", path)
            source = (release.PATCH_DIR / "release.py").read_text(encoding="utf-8")
            self.assertIn("policy_changes(candidate_dir, proposal_config, expected_head", source)

    def test_checkout_history_assertion_reads_the_proposed_workflow(self):
        yaml = release.yaml_module()
        source = Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_WORKFLOW") or
                      release.PATCH_DIR / "workflows/google-osconfig-agent-inventory.yml")
        with tempfile.TemporaryDirectory() as directory:
            document = yaml.safe_load(source.read_text(encoding="utf-8"))
            checkout = next(step for step in document["jobs"]["policy-check"]["steps"]
                            if step.get("with", {}).get("path") == "candidate")
            checkout["with"]["fetch-depth"] = 1
            candidate = Path(directory) / "proposed.yml"
            candidate.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
            with patch.dict(os.environ, {"OSCONFIG_POLICY_CANDIDATE_WORKFLOW": str(candidate)}):
                with self.assertRaises(AssertionError):
                    self.test_candidate_checkout_has_full_history_in_template_and_installed_workflow()

    def test_policy_task_requires_verified_delivery_to_exact_head_branch(self):
        state = {"number": 42, "config": "a" * 40, "head": "b" * 40,
                 "branch": "repair/osconfig-policy-exact"}
        captured = []
        def fake_api(path, **kwargs):
            captured.append((path, kwargs))
            return None
        with patch.object(release, "pages", return_value=[]), \
             patch.object(release, "api", side_effect=fake_api):
            release.request_policy_task("warelik/osconfig", state, "failure", "token")
        body = captured[-1][1]["data"]["body"]
        self.assertIn("commit and push", body)
        self.assertIn(state["branch"], body)
        self.assertIn("read back PR #42", body)
        self.assertIn("head.sha equals the pushed commit SHA", body)
        self.assertIn("Never force-push or create another PR", body)
        self.assertIn("fork-review-disposition:v1", body)
        self.assertIn(
            f"Trusted base: `{state['config']}`. Current repair SHA: `{state['head']}`.", body)
        self.assertIn("do not add candidate_id or create an owner receipt", body)
        self.assertIn('"finding_id":"actual native finding ID"', body)
        self.assertIn('"status":"fixed or disproved"', body)
        self.assertIn('"evidence":"..."', body)
        self.assertIn("`source_sha`", body)
        self.assertIn("specific regression test path and test name/assertion", body)
        self.assertIn("Use the existing authorized native owner API; no human approval is needed", body)
        self.assertIn(".vps/google-osconfig-agent/patches/check-upstream.sh", body)
        for path in sorted(release.POLICY_FILES):
            self.assertIn(f"`{path}`", body)
        for product_path in (release.PREFIX + "source.lock", release.PATCH_REL,
                             release.PREFIX + "rpm/google-osconfig-agent.spec",
                             release.PREFIX + "rpm/go-vendor-tools.toml"):
            self.assertNotIn(f"`{product_path}`", body)


class ReusableCommitIdentityTests(unittest.TestCase):
    def git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=cwd, check=True, text=True,
                              stdout=subprocess.PIPE).stdout.strip()

    def test_exact_tree_and_parent_are_required_for_retry_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            self.git("init", cwd=work)
            self.git("config", "user.name", "fixture", cwd=work)
            self.git("config", "user.email", "fixture@example.invalid", cwd=work)
            (work / "file").write_text("base\n")
            self.git("add", "file", cwd=work)
            self.git("commit", "-m", "base", cwd=work)
            base = self.git("rev-parse", "HEAD", cwd=work)
            tree = self.git("rev-parse", "HEAD^{tree}", cwd=work)
            self.git("commit", "--allow-empty", "-m", "first candidate", cwd=work)
            valid = self.git("rev-parse", "HEAD", cwd=work)
            self.assertEqual(release.verify_reusable_commit(
                work, valid, tree, base, "candidate branch"), valid)

            (work / "file").write_text("changed\n")
            self.git("commit", "-am", "wrong tree", cwd=work)
            wrong_tree = self.git("rev-parse", "HEAD", cwd=work)
            with self.assertRaisesRegex(ValueError, "unexpected tree or parent"):
                release.verify_reusable_commit(work, wrong_tree, tree, valid, "candidate branch")
            with self.assertRaisesRegex(ValueError, "unexpected tree or parent"):
                release.verify_reusable_commit(work, valid, tree, "f" * 40, "candidate branch")

    def test_api_failure_preserves_actionable_sanitized_detail(self):
        failure = subprocess.CalledProcessError(
            1, ["gh", "api"], stderr="permission denied Authorization: Bearer top-secret")
        with patch.object(subprocess, "run", side_effect=failure), \
             self.assertRaises(subprocess.CalledProcessError) as raised:
            release.api("repos/warelik/osconfig/pulls")
        self.assertIn("permission denied", raised.exception.stderr)
        self.assertNotIn("top-secret", raised.exception.stderr)


class FinalAttemptReuseTests(unittest.TestCase):
    candidate_id = "c" * 64
    run_sha = "a" * 40

    def attempt(self, *, candidate_id=None, job_status="completed", job_conclusion="success",
                step_status="completed", step_conclusion="success", started=True,
                step_name=None, run_id=701, run_attempt=2):
        step = {"name": step_name or release.POLICY_VALIDATION_STEP, "status": step_status,
                "conclusion": step_conclusion,
                "started_at": "2026-10-19T12:01:00Z" if started else None}
        return {"candidate_id": candidate_id or self.candidate_id,
                "run": {"id": run_id, "run_attempt": run_attempt},
                "jobs": [{"name": release.POLICY_VALIDATION_JOB,
                          "status": job_status, "conclusion": job_conclusion,
                          "steps": [step]}]}

    def history(self, *attempts):
        return {"complete": True, "attempts": list(attempts)}

    def test_policy_validation_is_separate_from_the_application_heavy_budget(self):
        self.assertEqual(release.FINAL_REQUIRED_JOBS, ("build-rpm", "sign"))
        self.assertFalse(release.policy_validation_state(
            self.history(), self.candidate_id)["validated"])
        self.assertFalse(release.native_policy_job_started({
            "started_at": "2026-10-19T12:00:00Z", "conclusion": "skipped", "steps": [],
        }))
        self.assertTrue(release.native_policy_job_started({
            "started_at": "2026-10-19T12:00:00Z", "conclusion": "failure",
            "steps": [{"name": release.POLICY_VALIDATION_STEP}],
        }))

    def test_successful_policy_unit_is_reused_only_for_its_exact_candidate(self):
        state = release.policy_validation_state(
            self.history(self.attempt(), self.attempt(candidate_id="d" * 64)),
            self.candidate_id)
        self.assertTrue(state["validated"])
        self.assertFalse(state["failed"])

    def test_active_failed_skipped_and_duplicate_policy_units_are_distinguished(self):
        active = release.policy_validation_state(
            self.history(self.attempt(job_status="in_progress", job_conclusion=None,
                                      step_status="in_progress", step_conclusion=None)),
            self.candidate_id)
        self.assertTrue(active["active"])
        failed = release.policy_validation_state(
            self.history(self.attempt(step_conclusion="failure")), self.candidate_id)
        self.assertTrue(failed["failed"])
        skipped = self.attempt(job_conclusion="skipped", step_status="completed",
                               step_conclusion="skipped", started=False)
        skipped["jobs"][0]["steps"] = []
        self.assertFalse(release.policy_validation_state(
            self.history(skipped), self.candidate_id)["validated"])
        duplicate = release.policy_validation_state(
            self.history(self.attempt(), self.attempt()), self.candidate_id)
        self.assertTrue(duplicate["failed"])

    def test_successful_bundle_receipt_is_reused_without_charging_a_policy_unit(self):
        attempt = self.attempt()
        attempt["jobs"][0]["steps"] = [{
            "name": "Reuse exact private bundle policy validation",
            "status": "completed", "conclusion": "success",
        }]
        state = release.policy_validation_state(self.history(attempt), self.candidate_id)
        self.assertTrue(state["validated"])
        self.assertFalse(state["failed"])

    def test_proposal_sandbox_success_and_failure_are_in_the_exact_candidate_ledger(self):
        success = self.attempt(step_name=release.POLICY_PROPOSAL_VALIDATION_STEP)
        state = release.policy_validation_state(self.history(success), self.candidate_id)
        self.assertTrue(state["validated"])
        self.assertFalse(state["failed"])

        failure = self.attempt(step_name=release.POLICY_PROPOSAL_VALIDATION_STEP,
                               step_conclusion="failure")
        state = release.policy_validation_state(self.history(failure), self.candidate_id)
        self.assertFalse(state["validated"])
        self.assertTrue(state["failed"])

    def test_proposal_bundle_reuse_success_failure_and_duplicate_callbacks_are_recorded(self):
        reuse_name = release.POLICY_PROPOSAL_BUNDLE_REUSE_STEP
        success = self.attempt(step_name=reuse_name, run_id=702)
        repeated = self.attempt(step_name=reuse_name, run_id=703)
        state = release.policy_validation_state(
            self.history(success, repeated), self.candidate_id)
        self.assertTrue(state["validated"])
        self.assertFalse(state["failed"])

        failure = self.attempt(step_name=reuse_name, step_conclusion="failure", run_id=704)
        state = release.policy_validation_state(self.history(failure), self.candidate_id)
        self.assertFalse(state["validated"])
        self.assertTrue(state["failed"])

        later_reuse = self.attempt(step_name=release.POLICY_PROPOSAL_HISTORY_REUSE_STEP,
                                   run_id=705)
        state = release.policy_validation_state(
            self.history(failure, later_reuse), self.candidate_id)
        self.assertFalse(state["validated"])
        self.assertTrue(state["failed"])

    def test_failed_proposal_sandbox_cannot_be_masked_by_later_reuse(self):
        failure = self.attempt(step_name=release.POLICY_PROPOSAL_VALIDATION_STEP,
                               step_conclusion="failure", run_id=705)
        reuse = self.attempt(step_name=release.POLICY_PROPOSAL_BUNDLE_REUSE_STEP,
                             run_id=706)
        state = release.policy_validation_state(self.history(failure, reuse), self.candidate_id)
        self.assertFalse(state["validated"])
        self.assertTrue(state["failed"])

    def test_prior_proposal_validation_reuse_step_is_itself_idempotent(self):
        first = self.attempt(step_name=release.POLICY_PROPOSAL_HISTORY_REUSE_STEP,
                             run_id=707)
        repeated = self.attempt(step_name=release.POLICY_PROPOSAL_HISTORY_REUSE_STEP,
                                run_id=708)
        state = release.policy_validation_state(
            self.history(first, repeated), self.candidate_id)
        self.assertTrue(state["validated"])
        self.assertFalse(state["failed"])

    def test_existing_reservation_preserves_policy_only_and_exact_owner_grant(self):
        grant_id = 92
        comment = {"body": "<!-- fork-final:v1 " + json.dumps({
            "schema": 1, "candidate_id": self.candidate_id,
            "run_id": 701, "run_attempt": 2, "workflow_sha": self.run_sha,
            "retry_grant_id": grant_id,
        }) + " -->"}
        decision = {"decision": "policy-only", "grant_id": grant_id}
        self.assertEqual(release.existing_reservation_decision(comment, decision), "policy-only")
        with self.assertRaisesRegex(ValueError, "exact authorization grant"):
            release.existing_reservation_decision(comment, {"decision": "policy-only"})

    def test_build_artifact_provenance_binds_files_to_exact_run_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_dir = root / "candidate"
            built_dir = root / "built"
            candidate_dir.mkdir()
            built_dir.mkdir()
            candidate = {
                "schema": 1, "repository": "warelik/osconfig",
                "upstream_sha": "a" * 40, "application_sha": "b" * 40,
                "configuration_sha": "c" * 40, "patchset_sha256": "d" * 64,
                "recipe_sha256": "e" * 64, "platform": "fedora-44/x86_64",
            }
            candidate_id = release.frozen_candidate_identity(candidate)
            (candidate_dir / "candidate-manifest.json").write_text(json.dumps({
                "candidate": candidate, "candidateIdentity": candidate_id,
                "candidateSha": self.run_sha,
            }), encoding="utf-8")
            rpm = built_dir / "agent.rpm"
            rpm.write_bytes(b"verified-rpm-bytes")
            class Core:
                @staticmethod
                def candidate_identity(value):
                    return candidate_id if value == candidate else "f" * 64
            with patch.object(release, "lifecycle_module", return_value=Core), \
                    patch.dict(os.environ, {
                        "GITHUB_RUN_ID": "701", "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_SHA": self.run_sha,
                        "EXPECTED_CANDIDATE_ID": candidate_id,
                    }):
                release.write_build_provenance(candidate_dir, built_dir)
                proof = release.verify_build_provenance(
                    candidate_dir, built_dir, 701, 2, self.run_sha, candidate_id)
                self.assertEqual(proof["run_attempt"], 2)
                rpm.write_bytes(b"changed-rpm-bytes")
                with self.assertRaisesRegex(ValueError, "differ from their exact attempt receipt"):
                    release.verify_build_provenance(
                        candidate_dir, built_dir, 701, 2, self.run_sha, candidate_id)


class PolicyLogPrivacyTests(unittest.TestCase):
    def test_shared_failure_hides_private_subprocess_output_without_changing_legacy_detail(self):
        private_detail = "/machine-maintenance/private-source.py: secret traceback text"
        shared = release.isolated_failure_message(
            "Immutable trusted publisher oracle", 1, private_detail, private_detail,
            shared=True)
        self.assertEqual(shared, "Immutable trusted publisher oracle failed with status 1")
        self.assertNotIn("private-source.py", shared)
        legacy = release.isolated_failure_message(
            "Isolated trusted publisher tests", 1, private_detail, private_detail,
            shared=False)
        self.assertIn("private-source.py", legacy)

    def test_public_test_summary_contains_only_frozen_filenames_and_exit_status(self):
        summary = release.policy_test_summary(
            ["/tmp/private-tree/test_release.py", "test_maintenance_adapter.py"],
            returncode=1)
        self.assertEqual(summary,
                         "Policy tests [test_maintenance_adapter.py, test_release.py]: FAIL exit=1")


class OpenApplicationSourceContinuityTests(unittest.TestCase):
    repo = "warelik/osconfig"
    config = "a" * 40
    baseline_config = "b" * 40
    baseline_application = "c" * 40
    upstream = "d" * 40
    application = "e" * 40
    delta_sha = "f" * 40
    review_source = "1" * 40

    def write_recipe_tree(self, root, source_lock):
        root = Path(root)
        for relative in release.PRODUCT_RECIPE_INPUTS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source_lock if relative == "source.lock"
                             else b"trusted recipe input:" + relative.encode("utf-8"))

    def recipe_sha(self, source_lock):
        with tempfile.TemporaryDirectory() as temporary:
            self.write_recipe_tree(temporary, source_lock)
            return release.recipe_digest(temporary)

    def pair(self):
        source_lock = (json.dumps({
            "tag": "20261015.00", "commit": self.upstream,
            "archiveSha256": "4" * 64,
        }, indent=2) + "\n").encode("utf-8")
        candidate = {
            "schema": 1, "repository": self.repo, "upstream_sha": self.upstream,
            "application_sha": self.application, "configuration_sha": self.delta_sha,
            "patchset_sha256": "2" * 64, "recipe_sha256": self.recipe_sha(source_lock),
            "platform": "fedora-44/x86_64",
        }
        candidate_id = release.frozen_candidate_identity(candidate)
        branch_key = hashlib.sha256(
            (self.config + "\0" + self.baseline_config).encode()).hexdigest()
        full_branch = f"review/{self.upstream}-{branch_key}"
        delta_branch = f"review/changes-{self.delta_sha}"
        full_state = {
            "schema": 2, "sourceConfig": self.config, "upstream": self.upstream,
            "tag": "20261015.00", "archiveSha256": "4" * 64,
            "seed": self.review_source, "candidate": candidate,
            "candidateId": candidate_id, "applicationSha": self.application,
            "reviewSourceSha": self.review_source,
            "baselineConfig": self.baseline_config, "deltaSha": self.delta_sha,
            "deltaPr": 102,
        }
        full = {
            "number": 101, "state": "open",
            "user": {"login": self.repo.split("/", 1)[0], "type": "User"},
            "base": {"ref": f"review-base/{self.upstream}", "sha": self.upstream,
                     "repo": {"full_name": self.repo}},
            "head": {"ref": full_branch, "sha": self.review_source,
                     "repo": {"full_name": self.repo}},
            "body": "<!-- osconfig-candidate:v2 "
                    + json.dumps(full_state, sort_keys=True, separators=(",", ":")) + " -->",
        }
        delta = {
            "number": 102, "state": "open",
            "base": {"ref": f"review-base/{self.baseline_config}", "sha": self.baseline_config,
                     "repo": {"full_name": self.repo}},
            "head": {"ref": delta_branch, "sha": self.delta_sha,
                     "repo": {"full_name": self.repo}},
            "body": "<!-- osconfig-delta:v2 " + json.dumps({
                "candidateId": candidate_id, "candidate": candidate,
                "sourceConfig": self.config, "baselineConfig": self.baseline_config,
            }, sort_keys=True, separators=(",", ":")) + " -->",
        }
        refs = {
            f"refs/heads/review-base/{self.upstream}": self.upstream,
            f"refs/heads/{full_branch}": self.review_source,
            f"refs/heads/review-base/{self.baseline_config}": self.baseline_config,
            f"refs/heads/{delta_branch}": self.delta_sha,
        }
        return full, delta, refs, source_lock

    def check(self, pulls, delta, refs, source_lock):
        def read_api(path, **_kwargs):
            delta_path = f"repos/{self.repo}/pulls/102"
            if path == delta_path:
                return delta
            prefix = f"repos/{self.repo}/git/ref/heads/"
            if path.startswith(prefix):
                name = "refs/heads/" + path[len(prefix):]
                return {"ref": name, "object": {"type": "commit", "sha": refs[name]}}
            raise AssertionError(f"Unexpected API path: {path}")

        def read_content(repo, path, ref):
            if (repo, path, ref) != (self.repo, release.PREFIX + "source.lock", self.application):
                raise AssertionError("Candidate lock was not read from its exact application commit")
            if source_lock is None:
                raise AssertionError("No source lock was expected for this nonmatching PR")
            return source_lock

        class Core:
            @staticmethod
            def candidate_identity(value):
                return release.frozen_candidate_identity(value)

        with patch.object(release, "pages", return_value=pulls), \
                patch.object(release, "api", side_effect=read_api), \
                patch.object(release, "content", side_effect=read_content), \
                patch.object(release, "find_review_pull", return_value=delta), \
                patch.object(release, "_orphan_application_source", return_value=None), \
                patch.object(release, "lifecycle_module", return_value=Core):
            result = release.matching_open_application_source(
                self.repo, self.config,
                {"candidate": {"configuration_sha": self.baseline_config,
                               "application_sha": self.baseline_application,
                               "upstream_sha": self.upstream}})
        return result

    def test_pending_pair_holds_its_exact_source_when_latest_can_advance(self):
        full, delta, refs, source_lock = self.pair()
        self.assertEqual(self.check([full], delta, refs, source_lock), {
            "tag": "20261015.00", "commit": self.upstream, "archiveSha256": "4" * 64,
            "sourceLock": source_lock,
        })

    def test_held_raw_source_lock_preserves_candidate_recipe_identity(self):
        full, delta, refs, source_lock = self.pair()
        held = self.check([full], delta, refs, source_lock)
        candidate = json.loads(release.CANDIDATE_MARKER.search(full["body"]).group(1))["candidate"]
        self.assertEqual(held["sourceLock"], source_lock)
        with tempfile.TemporaryDirectory() as temporary:
            self.write_recipe_tree(temporary, held["sourceLock"])
            recipe_root = Path(temporary)
            self.assertEqual(release.recipe_digest(recipe_root), candidate["recipe_sha256"])
            source_lock_path = recipe_root / "source.lock"
            sorted_lock = json.dumps(json.loads(source_lock.decode("utf-8")),
                                     sort_keys=True, separators=(",", ":")).encode() + b"\n"
            self.assertNotEqual(sorted_lock, source_lock)
            source_lock_path.write_bytes(sorted_lock)
            self.assertNotEqual(release.recipe_digest(recipe_root), candidate["recipe_sha256"])
            source_lock_path.write_bytes(held["sourceLock"])
            self.assertEqual(release.recipe_digest(recipe_root), candidate["recipe_sha256"])

    def test_existing_manual_candidate_id_branch_is_also_held(self):
        full, delta, refs, source_lock = self.pair()
        identity = json.loads(release.CANDIDATE_MARKER.search(full["body"]).group(1))
        old_branch = full["head"]["ref"]
        full["head"]["ref"] = f"review/{self.upstream}-{identity['candidateId']}"
        refs.pop(f"refs/heads/{old_branch}")
        refs[f"refs/heads/{full['head']['ref']}"] = self.review_source
        self.assertEqual(self.check([full], delta, refs, source_lock), {
            "tag": "20261015.00", "commit": self.upstream, "archiveSha256": "4" * 64,
            "sourceLock": source_lock,
        })

    def test_no_pair_selects_latest_and_stale_config_or_baseline_does_not_hold(self):
        self.assertIsNone(self.check([], None, {}, None))
        for field, stale in (("sourceConfig", "5" * 40),
                             ("baselineConfig", "6" * 40)):
            with self.subTest(field=field):
                full, delta, refs, source_lock = self.pair()
                identity_text = release.CANDIDATE_MARKER.search(full["body"]).group(1)
                identity = json.loads(identity_text)
                identity[field] = stale
                full["body"] = "<!-- osconfig-candidate:v2 " + json.dumps(
                    identity, sort_keys=True, separators=(",", ":")) + " -->"
                old_config = stale if field == "sourceConfig" else self.config
                old_baseline = stale if field == "baselineConfig" else self.baseline_config
                old_key = hashlib.sha256((old_config + "\0" + old_baseline).encode()).hexdigest()
                full["head"]["ref"] = f"review/{self.upstream}-{old_key}"
                self.assertIsNone(self.check([full], delta, refs, source_lock))

    def test_current_candidate_rejects_malformed_duplicate_and_changed_refs(self):
        full, delta, refs, source_lock = self.pair()
        malformed = dict(full, body=full["body"] + "\n" + full["body"])
        with self.assertRaisesRegex(ValueError, "unique identity marker"):
            self.check([malformed], delta, refs, source_lock)

        duplicate = dict(full, number=103)
        with self.assertRaisesRegex(ValueError, "Multiple open OS Config candidate pairs"):
            self.check([full, duplicate], delta, refs, source_lock)

        changed_refs = dict(refs)
        changed_refs[f"refs/heads/{full['head']['ref']}"] = "9" * 40
        with self.assertRaisesRegex(ValueError, "full review PR or refs changed"):
            self.check([full], delta, changed_refs, source_lock)

    def test_foreign_or_unauthorized_malformed_candidate_prs_are_ignored_before_native_reads(self):
        full, _delta, _refs, _source_lock = self.pair()
        foreign = dict(full, body="<!-- osconfig-candidate:v2 {malformed")
        foreign["head"] = dict(full["head"], repo={"full_name": "fork/osconfig"})
        unauthorized = dict(full, body="")
        unauthorized["user"] = {"login": "other-user", "type": "User"}

        with patch.object(release, "pages", return_value=[foreign, unauthorized]), \
                patch.object(release, "api") as native_api, \
                patch.object(release, "content") as native_content, \
                patch.object(release, "find_review_pull") as delta_lookup, \
                patch.object(release, "_orphan_application_source", return_value=None), \
                patch.object(release, "lifecycle_module") as lifecycle:
            result = release.matching_open_application_source(
                self.repo, self.config,
                {"candidate": {"configuration_sha": self.baseline_config,
                               "application_sha": self.baseline_application,
                               "upstream_sha": self.upstream}})
        self.assertIsNone(result)
        native_api.assert_not_called()
        native_content.assert_not_called()
        delta_lookup.assert_not_called()
        lifecycle.assert_not_called()


class ApplicationSourceContinuityWorkflowTests(unittest.TestCase):
    def test_source_pair_is_checked_before_latest_and_locked_recipe_is_staged_verbatim(self):
        path = release.ROOT / release.WORKFLOW_PATH
        document = release.yaml_module().safe_load(path.read_text(encoding="utf-8"))
        steps = document["jobs"]["candidate-source"]["steps"]
        preflight = next(index for index, step in enumerate(steps)
                         if step.get("id") == "source-preflight")
        latest = next(index for index, step in enumerate(steps)
                      if step.get("name") == "Resolve latest upstream release")
        held = next(step for step in steps
                    if step.get("name") == "Prepare the exact held upstream source")
        self.assertLess(preflight, latest)
        self.assertIn("application-source-preflight", steps[preflight]["run"])
        self.assertIn("steps.source-preflight.outputs.held != 'true'", steps[latest]["if"])
        self.assertIn("steps.source-preflight.outputs.held == 'true'", held["if"])
        self.assertIn("install -m 700 .vps/google-osconfig-agent/patches/prepare-source.sh", held["run"])
        self.assertIn("cmp -- .vps/google-osconfig-agent/patches/prepare-source.sh", held["run"])
        self.assertIn("SOURCE_LOCK_BASE64", held["env"])
        self.assertIn("base64.b64decode", held["run"])
        self.assertIn("stream.write(source_lock)", held["run"])
        self.assertIn("bash \"$locked_tool/prepare-source.sh\" --locked", held["run"])


class NativeFinalHistoryReservationActorTests(unittest.TestCase):
    repo = "warelik/osconfig"
    current_candidate = {"candidate": "current"}
    prior_candidate = {"candidate": "prior"}
    current_id = "a" * 64
    prior_id = "b" * 64
    workflow_sha = "c" * 40

    def reservation(self, actor, *, malformed=False, comment_id=51):
        final_value = {
            "schema": 1, "candidate_id": self.prior_id,
            "run_id": 701, "run_attempt": 1, "workflow_sha": self.workflow_sha,
        }
        candidate_marker = (
            "<!-- fork-candidate:v1 "
            + json.dumps(self.prior_candidate, sort_keys=True, separators=(",", ":"))
            + " -->"
        )
        final_marker = ("<!-- fork-final:v1 {malformed} -->" if malformed else
                        "<!-- fork-final:v1 "
                        + json.dumps(final_value, sort_keys=True, separators=(",", ":"))
                        + " -->")
        return {
            "id": comment_id,
            "user": actor,
            "issue_url": f"https://api.github.com/repos/{self.repo}/issues/18",
            "created_at": "2026-10-20T12:01:00Z",
            "updated_at": "2026-10-20T12:01:00Z",
            "body": candidate_marker + "\n" + final_marker,
        }

    def retry_grant(self, actor, *, malformed=False, comment_id=71):
        marker = {
            "schema": 1, "candidate_id": self.current_id,
            "previous_run_id": 701, "previous_run_attempt": 1,
        }
        body = ("<!-- fork-final-retry:v1 {malformed} -->" if malformed else
                "<!-- fork-final-retry:v1 "
                + json.dumps(marker, sort_keys=True, separators=(",", ":")) + " -->")
        return {
            "id": comment_id,
            "user": actor,
            "issue_url": f"https://api.github.com/repos/{self.repo}/issues/17",
            "created_at": "2026-10-20T12:01:00Z",
            "updated_at": "2026-10-20T12:01:00Z",
            "body": body,
        }

    def gather(self, comments, *, runs=(), jobs=()):
        def read_pages(path):
            if path == f"repos/{self.repo}/issues/comments":
                return comments
            if path.endswith("/jobs"):
                return list(jobs)
            raise AssertionError(f"Unexpected paginated route: {path}")

        def read_api(path):
            if path == f"repos/{self.repo}/actions/runs/701/attempts/1":
                return {
                    "id": 701, "run_attempt": 1,
                    "updated_at": "2026-10-20T12:03:00Z",
                    "head_sha": self.workflow_sha,
                }
            raise AssertionError(f"Unexpected API route: {path}")

        class Core:
            @staticmethod
            def candidate_identity(candidate):
                if candidate == self.current_candidate:
                    return self.current_id
                if candidate == self.prior_candidate:
                    return self.prior_id
                raise AssertionError("Unexpected candidate identity input")

        with patch.object(release, "lifecycle_module", return_value=Core), \
                patch.object(release, "pages", side_effect=read_pages), \
                patch.object(release, "native_workflow_runs", return_value=list(runs)), \
                patch.object(release, "api", side_effect=read_api), \
                patch.dict(os.environ, {"CANDIDATE_PR": "17"}):
            return release.native_final_history(
                self.repo, self.current_candidate,
                {"published_at": "2026-10-20T12:00:00Z"},
                current_run_id=999, current_run_attempt=1)

    def test_untrusted_valid_duplicate_and_malformed_reservations_do_not_enter_history(self):
        attacker = {"login": "public-user", "type": "User"}
        comments = [
            self.reservation(attacker, comment_id=51),
            self.reservation(attacker, comment_id=52),
            self.reservation(attacker, malformed=True, comment_id=53),
        ]
        history = self.gather(comments)
        self.assertTrue(history["complete"])
        self.assertEqual(history["attempts"], [])

    def test_malformed_trusted_reservation_makes_native_history_incomplete(self):
        trusted_bot = {"login": "github-actions[bot]", "type": "Bot"}
        history = self.gather([self.reservation(trusted_bot, malformed=True)])
        self.assertFalse(history["complete"])
        self.assertEqual(history["attempts"], [])

    def test_untrusted_retry_grant_markers_are_ignored_before_parsing(self):
        attacker = {"login": "public-user", "type": "User"}
        history = self.gather([
            self.retry_grant(attacker, comment_id=71),
            self.retry_grant(attacker, malformed=True, comment_id=72),
        ])
        self.assertTrue(history["complete"])
        self.assertEqual(history["grants"], [])

    def test_owner_retry_grant_is_counted_and_malformed_owner_grant_fails_closed(self):
        owner = {"login": "warelik", "type": "User"}
        accepted = self.gather([self.retry_grant(owner)])
        self.assertTrue(accepted["complete"])
        self.assertEqual([grant["id"] for grant in accepted["grants"]], [71])

        malformed = self.gather([self.retry_grant(owner, malformed=True)])
        self.assertFalse(malformed["complete"])
        self.assertEqual(malformed["grants"], [])

    def test_trusted_historical_reservation_still_counts_its_exact_attempt(self):
        trusted_bot = {"login": "github-actions[bot]", "type": "Bot"}
        jobs = [
            {"id": 7011, "name": "build-rpm", "status": "completed",
             "conclusion": "success", "started_at": "2026-10-20T12:01:30Z",
             "completed_at": "2026-10-20T12:02:00Z", "steps": [{"name": "Build"}]},
            {"id": 7012, "name": "sign", "status": "completed",
             "conclusion": "success", "started_at": "2026-10-20T12:02:00Z",
             "completed_at": "2026-10-20T12:03:00Z", "steps": [{"name": "Sign"}]},
        ]
        history = self.gather(
            [self.reservation(trusted_bot)],
            runs=[{"id": 701, "run_attempt": 1,
                   "updated_at": "2026-10-20T12:03:00Z"}],
            jobs=jobs)
        self.assertTrue(history["complete"])
        self.assertEqual(len(history["attempts"]), 1)
        attempt = history["attempts"][0]
        self.assertEqual(attempt["candidate_id"], self.prior_id)
        self.assertEqual((attempt["run"]["id"], attempt["run"]["run_attempt"]), (701, 1))
        self.assertEqual(attempt["reservation"]["id"], 51)
        self.assertEqual([job["name"] for job in attempt["jobs"]], ["build-rpm", "sign"])


class CurrentFinalReservationActorTests(unittest.TestCase):
    repo = "warelik/osconfig"
    candidate = {"candidate": "current"}
    candidate_id = "a" * 64
    workflow_sha = "c" * 40

    def comment(self, actor, *, malformed=False, comment_id=81):
        candidate_marker = (
            "<!-- fork-candidate:v1 "
            + json.dumps(self.candidate, sort_keys=True, separators=(",", ":"))
            + " -->"
        )
        final = {
            "schema": 1, "candidate_id": self.candidate_id,
            "run_id": 701, "run_attempt": 2, "workflow_sha": self.workflow_sha,
        }
        final_marker = ("<!-- fork-final:v1 {malformed} -->" if malformed else
                        "<!-- fork-final:v1 "
                        + json.dumps(final, sort_keys=True, separators=(",", ":"))
                        + " -->")
        return {"id": comment_id, "user": actor,
                "body": candidate_marker + "\n" + final_marker}

    def read(self, comments):
        class Core:
            @staticmethod
            def candidate_identity(value):
                if value == self.candidate:
                    return self.candidate_id
                raise AssertionError("Unexpected final-reservation candidate")

        with patch.object(release, "lifecycle_module", return_value=Core), \
                patch.object(release, "pages", return_value=comments):
            return release.current_final_reservation(
                self.repo, 17, self.candidate, 701, 2, self.workflow_sha)

    def test_public_markers_cannot_shadow_or_malformed_fail_current_reservation(self):
        outsider = {"login": "public-user", "type": "User"}
        self.assertIsNone(self.read([self.comment(outsider)]))
        self.assertIsNone(self.read([self.comment(outsider, malformed=True)]))
        workflow_bot = {"login": "github-actions[bot]", "type": "Bot"}
        trusted = self.comment(workflow_bot, comment_id=83)
        self.assertIs(self.read([
            self.comment(outsider),
            self.comment(outsider, malformed=True, comment_id=82),
            trusted,
        ]), trusted)

    def test_malformed_trusted_current_reservation_fails_closed(self):
        workflow_bot = {"login": "github-actions[bot]", "type": "Bot"}
        with self.assertRaisesRegex(ValueError, "Trusted current final reservation metadata is malformed"):
            self.read([self.comment(workflow_bot, malformed=True)])
        valid = self.comment(workflow_bot, comment_id=83)
        with self.assertRaisesRegex(ValueError, "Trusted current final reservation metadata is malformed"):
            self.read([self.comment(workflow_bot, malformed=True), valid])
        with self.assertRaisesRegex(ValueError, "duplicate final reservations"):
            self.read([valid, self.comment(workflow_bot, comment_id=84)])

    def test_exact_trusted_current_reservation_still_matches(self):
        workflow_bot = {"login": "github-actions[bot]", "type": "Bot"}
        comment = self.comment(workflow_bot)
        self.assertIs(self.read([comment]), comment)


class PostPublicationAdoptionTests(unittest.TestCase):
    repo = "warelik/osconfig"

    def manifest(self):
        candidate = {
            "schema": 1, "repository": self.repo,
            "upstream_sha": "a" * 40, "application_sha": "b" * 40,
            "configuration_sha": "c" * 40, "patchset_sha256": "d" * 64,
            "recipe_sha256": "e" * 64, "platform": "fedora-44/x86_64",
        }
        old_baseline = {
            "repository": self.repo, "candidate": {**candidate, "configuration_sha": "f" * 40},
        }
        config, full_sha = "1" * 40, "2" * 40
        return {
            "candidate": candidate,
            "candidateApplicationSha": candidate["application_sha"],
            "candidateIdentity": "3" * 64,
            "upstreamCommit": candidate["upstream_sha"],
            "candidateSha": full_sha,
            "configSha": config,
            "upstreamArchiveSha256": "4" * 64,
            "patchSha256": "5" * 64,
            "specSha256": "6" * 64,
            "acceptedBaselineProof": {
                "variable": {"value": json.dumps(old_baseline)},
            },
            "reviewContexts": {
                "full": {"review_sha": full_sha},
                "delta": {"review_sha": candidate["configuration_sha"]},
            },
        }

    def test_postpublication_transition_is_enabled_only_after_exact_signed_manifest(self):
        manifest = self.manifest()
        config = manifest["configSha"]
        published = {
            key: manifest[key] for key in (
                "candidateSha", "upstreamCommit", "upstreamArchiveSha256",
                "patchSha256", "specSha256",
            )
        }
        settings = {
            "github_owner": "warelik", "github_repo": "osconfig",
            "signing_fingerprint": "A" * 40,
        }
        events = []
        signed = Mock(side_effect=lambda *_args: events.append("signed") or published)
        transition = Mock(side_effect=lambda *_args: (
            events.append("transition") or (
                "exact-native-value",
                {"published_at": "2026-10-21T12:00:00Z"},
                "7" * 64,
            )
        ))
        pair = {"state": "ready", "complete": True}
        pair_check = Mock(side_effect=lambda *_args, **_kwargs:
                          events.append("review") or ({}, {}, pair))
        with tempfile.TemporaryDirectory(prefix="osconfig-postpublication-review-") as temporary:
            candidate_dir = Path(temporary)
            (candidate_dir / "candidate-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            with patch.dict(os.environ, {
                    "GITHUB_REPOSITORY": self.repo,
                    "OSCONFIG_RPM_SIGNING_FINGERPRINT": "A" * 40,
                }, clear=False), \
                    patch.object(release, "repository_settings", return_value=settings), \
                    patch.object(release, "api", return_value={"sha": config}), \
                    patch.object(release, "verify_manifest_files", signed), \
                    patch.object(release, "accepted_baseline_checkpoint", transition), \
                    patch.object(release, "review_pair_status", pair_check):
                result = release.verify_candidate_artifact(
                    candidate_dir, Path(temporary) / "pages", allow_default_advanced=True)
        self.assertEqual(events, ["signed", "transition", "review"])
        self.assertEqual(pair_check.call_args.kwargs["signed_transition"], {
            "value": "exact-native-value", "published_at": "2026-10-21T12:00:00Z",
        })
        self.assertEqual(result[0], self.repo)

        bad_published = {**published, "candidateSha": "8" * 40}
        signed.reset_mock(side_effect=True, return_value=True)
        signed.side_effect = lambda *_args: events.append("signed-bad") or bad_published
        transition.reset_mock()
        pair_check.reset_mock()
        events.clear()
        with tempfile.TemporaryDirectory(prefix="osconfig-postpublication-wrong-manifest-") as temporary:
            candidate_dir = Path(temporary)
            (candidate_dir / "candidate-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            with patch.dict(os.environ, {
                    "GITHUB_REPOSITORY": self.repo,
                    "OSCONFIG_RPM_SIGNING_FINGERPRINT": "A" * 40,
                }, clear=False), \
                    patch.object(release, "repository_settings", return_value=settings), \
                    patch.object(release, "api", return_value={"sha": config}), \
                    patch.object(release, "verify_manifest_files", signed), \
                    patch.object(release, "accepted_baseline_checkpoint", transition), \
                    patch.object(release, "review_pair_status", pair_check):
                with self.assertRaisesRegex(ValueError, "does not identify the exact reviewed candidate"):
                    release.verify_candidate_artifact(
                        candidate_dir, Path(temporary) / "pages", allow_default_advanced=True)
        self.assertEqual(events, ["signed-bad"])
        transition.assert_not_called()
        pair_check.assert_not_called()


class AlreadyAdoptedProductInputTests(unittest.TestCase):
    repo = "warelik/osconfig"

    def run_adopt(self, *, mismatched_path=None):
        package_evr = next(
            line.partition("=")[2]
            for line in (release.ROOT / release.REPOSITORY_CONF).read_text(encoding="utf-8").splitlines()
            if line.startswith("minimum_evr=")
        )
        manifest = {"configSha": "a" * 40, "candidatePr": 71, "deltaPr": 72,
                    "reviewContexts": {"full": {}, "delta": {}}}
        latest = "b" * 40
        settings = {"minimum_evr": package_evr}
        published = {"packageEvr": package_evr}
        files = {}
        with tempfile.TemporaryDirectory(prefix="osconfig-already-adopted-inputs-") as temporary:
            root = Path(temporary)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            for relative in (*release.PRODUCT_BUILD_INPUTS, "source.lock"):
                payload = f"candidate bytes for {relative}\n".encode("utf-8")
                (candidate_dir / Path(relative).name).write_bytes(payload)
                files[release.PREFIX + relative] = payload
            config_lines = (release.ROOT / release.REPOSITORY_CONF).read_text(
                encoding="utf-8").splitlines()
            minimum = [index for index, line in enumerate(config_lines)
                       if line.startswith("minimum_evr=")]
            self.assertEqual(len(minimum), 1)
            config_lines[minimum[0]] = f"minimum_evr={package_evr}"
            files[release.REPOSITORY_CONF] = ("\n".join(config_lines) + "\n").encode()
            if mismatched_path is not None:
                files[mismatched_path] = b"different package input\n"

            def content(repo, path, revision):
                self.assertEqual((repo, revision), (self.repo, release.DEFAULT_BRANCH))
                return files[path]

            advanced = Mock()
            closed = Mock()
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": self.repo}, clear=False), \
                    patch.object(release, "verify_candidate_artifact",
                                 return_value=(self.repo, manifest, settings, "A" * 40,
                                               published, latest)), \
                    patch.object(release, "api", return_value={"sha": latest}), \
                    patch.object(release, "content", side_effect=content), \
                    patch.object(release, "owner_token", return_value="fixture-token"), \
                    patch.object(release, "advance_accepted_baseline", advanced), \
                    patch.object(release, "close_candidate", closed):
                if mismatched_path is None:
                    release.adopt(candidate_dir, root / "pages")
                else:
                    with self.assertRaisesRegex(
                            ValueError, "Default branch advanced with different package state"):
                        release.adopt(candidate_dir, root / "pages")
            return advanced, closed

    def test_already_adopted_acceptance_checks_all_six_signed_package_inputs(self):
        advanced, closed = self.run_adopt()
        advanced.assert_called_once()
        closed.assert_called_once()
        for relative in (*release.PRODUCT_BUILD_INPUTS, "source.lock"):
            with self.subTest(path=relative):
                advanced, closed = self.run_adopt(mismatched_path=release.PREFIX + relative)
                advanced.assert_not_called()
                closed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
