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
        self.assertIn("sign", repair["needs"])
        self.assertIn("recover-validated", repair["needs"])
        self.assertIn("needs.review.result == 'failure'", repair["if"])
        self.assertIn("needs.sign.result == 'failure'", repair["if"])
        self.assertIn("needs.recover-validated.result == 'failure'", repair["if"])
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


class PolicyWorkflowAndSharedValidationTests(unittest.TestCase):
    repo = "warelik/osconfig"

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
            product_file.parent.mkdir(parents=True)
            policy_file.parent.mkdir(parents=True)
            product_file.write_text("product recipe\n", encoding="utf-8")
            policy_file.write_text("trusted controller\n", encoding="utf-8")
            hashes = {str(product_file): "a" * 40, str(policy_file): "b" * 40}
            tree = {"truncated": False, "tree": [
                {"path": release.PREFIX + "build-rpm.sh", "mode": "100644", "sha": "a" * 40,
                 "type": "blob"},
                {"path": release.PREFIX + "release.py", "mode": "100644", "sha": "b" * 40,
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
        candidate = {"schema": 1, "repository": repo}
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
             patch.object(release, "lifecycle_module", return_value=Core):
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
            ".vps/google-osconfig-agent/patches/README.md",
            ".vps/google-osconfig-agent/patches/maintenance.py",
            ".vps/google-osconfig-agent/patches/maintenance.lock.json",
            ".vps/google-osconfig-agent/patches/tests/test_release.py",
            ".vps/google-osconfig-agent/patches/tests/test_policy_isolation.py",
            ".vps/google-osconfig-agent/patches/tests/test_maintenance_adapter.py",
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
        adapter_test = ".vps/google-osconfig-agent/patches/tests/test_maintenance_adapter.py"
        self.assertEqual(release.validate_policy_paths([adapter_test]), [adapter_test])
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
                    expected = "non-regular or malformed" if kind == "mode" else "incomplete"
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
                step_status="completed", step_conclusion="success", started=True):
        step = {"name": release.POLICY_VALIDATION_STEP, "status": step_status,
                "conclusion": step_conclusion,
                "started_at": "2026-10-19T12:01:00Z" if started else None}
        return {"candidate_id": candidate_id or self.candidate_id,
                "run": {"id": 701, "run_attempt": 2},
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
            candidate = {"schema": 1}
            (candidate_dir / "candidate-manifest.json").write_text(json.dumps({
                "candidate": candidate, "candidateIdentity": self.candidate_id,
                "candidateSha": self.run_sha,
            }), encoding="utf-8")
            rpm = built_dir / "agent.rpm"
            rpm.write_bytes(b"verified-rpm-bytes")
            class Core:
                @staticmethod
                def candidate_identity(value):
                    return "c" * 64 if value == candidate else "d" * 64
            with patch.object(release, "lifecycle_module", return_value=Core), \
                    patch.dict(os.environ, {
                        "GITHUB_RUN_ID": "701", "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_SHA": self.run_sha,
                        "EXPECTED_CANDIDATE_ID": self.candidate_id,
                    }):
                release.write_build_provenance(candidate_dir, built_dir)
                proof = release.verify_build_provenance(
                    candidate_dir, built_dir, 701, 2, self.run_sha, self.candidate_id)
                self.assertEqual(proof["run_attempt"], 2)
                rpm.write_bytes(b"changed-rpm-bytes")
                with self.assertRaisesRegex(ValueError, "differ from their exact attempt receipt"):
                    release.verify_build_provenance(
                        candidate_dir, built_dir, 701, 2, self.run_sha, self.candidate_id)


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


if __name__ == "__main__":
    unittest.main()
