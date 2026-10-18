#!/usr/bin/env python3
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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
                        "EXPECTED_CANDIDATE_SHA": "${{ needs.prepare.outputs.sha }}",
                        "EXPECTED_UPSTREAM_SHA": "${{ needs.prepare.outputs.upstream }}",
                        "EXPECTED_PATCH_SHA": "${{ needs.prepare.outputs.patch }}",
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
                self.assertNotIn("\\\n", command)

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
            checkout = document["jobs"]["sign"]["steps"][0]
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
        self.assertIn("sign", repair["needs"])
        self.assertIn("needs.review.result == 'failure'", repair["if"])
        self.assertIn("needs.sign.result == 'failure'", repair["if"])
        self.assertIn("release.py repair-policy", repair["steps"][-1].get("run", ""))


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
        bootstrap = [step for step in steps
                     if step.get("name") == "Install independent policy bootstrap parser"]
        self.assertEqual(len(bootstrap), 1)
        install = bootstrap[0]["run"]
        self.assertIn("pip install", install)
        self.assertIn("--only-binary=:all:", install)
        self.assertIn("--require-hashes", install)
        self.assertIn("osconfig-policy-bootstrap", install)
        self.assertIn("-r trusted/.vps/google-osconfig-agent/patches/requirements-policy-bootstrap.txt", install)
        self.assertNotIn("trusted/.vps/google-osconfig-agent/patches/requirements-policy.txt", install)
        self.assertNotIn(">=6,<7", install)
        check = [step for step in steps if "release.py policy-check candidate" in step.get("run", "")]
        self.assertEqual(len(check), 1)
        self.assertIn("osconfig-policy-bootstrap", check[0].get("env", {}).get("PYTHONPATH", ""))


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


class PublisherPolicyScopeTests(unittest.TestCase):
    def test_release_policy_files_are_separate_from_application_patch(self):
        expected = {
            ".vps/google-osconfig-agent/patches/release.py",
            ".vps/google-osconfig-agent/patches/tests/test_release.py",
            ".vps/google-osconfig-agent/patches/tests/test_policy_isolation.py",
            ".vps/google-osconfig-agent/patches/tests/signing.sh",
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
                source = release.PATCH_DIR / relative
                payload = source.read_bytes()
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
                 patch.object(release, "check_cached_whitespace",
                              wraps=release.check_cached_whitespace) as whitespace_check, \
                 patch.dict(os.environ, {}, clear=False):
                if bad_ordinary_file:
                    with self.assertRaises(release.CommandFailure):
                        release.adopt(candidate, root / "pages")
                else:
                    release.adopt(candidate, root / "pages")
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

class PaginationAndApiDiagnosticsTests(unittest.TestCase):
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
        manifest = {
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
            ancestry = next(step for step in steps
                            if step.get("name") ==
                            "Verify the exact proposal has complete ancestry")
            self.assertEqual(ancestry["env"]["POLICY_BASE_SHA"],
                             "${{ steps.identity.outputs.config }}", path)
            self.assertEqual(ancestry["env"]["POLICY_HEAD_SHA"],
                             "${{ steps.identity.outputs.head }}", path)
            self.assertEqual(
                ancestry["run"],
                'git -C candidate merge-base --is-ancestor '
                '"$POLICY_BASE_SHA" "$POLICY_HEAD_SHA"',
                path,
            )

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


if __name__ == "__main__":
    unittest.main()
