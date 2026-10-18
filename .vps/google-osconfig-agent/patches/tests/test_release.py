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


class ParserRequirementTests(unittest.TestCase):
    def test_parser_requirement_accepts_an_exact_future_pyyaml_version(self):
        for version in ("6.0.3", "999999.0.0", "7.0rc1+policy.2"):
            with self.subTest(version=version):
                self.assertEqual(
                    release.parser_requirement_version(f"# trusted comment\nPyYAML=={version}\n"),
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
        steps = document["jobs"]["policy-check"]["steps"]
        bootstrap = [step for step in steps
                     if step.get("name") == "Install independent policy bootstrap parser"]
        self.assertEqual(len(bootstrap), 1)
        install = bootstrap[0]["run"]
        self.assertIn("pip install", install)
        self.assertIn("PyYAML", install)
        self.assertIn("--only-binary=:all:", install)
        self.assertIn("osconfig-policy-bootstrap", install)
        self.assertNotIn("requirements-policy.txt", install)
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
            ".vps/google-osconfig-agent/patches/workflows/google-osconfig-agent-inventory.yml",
            ".vps/google-osconfig-agent/patches/requirements-policy.txt",
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

            app_patch = work / (release.PREFIX + "osconfig-inventory.patch")
            app_patch.write_text("application change\n", encoding="utf-8")
            self.git("add", "--", release.PREFIX + "osconfig-inventory.patch", cwd=work)
            self.git("commit", "-m", "mixed application change", cwd=work)
            mixed_head = self.git("rev-parse", "HEAD", cwd=work)
            self.git("push", "origin", f"{mixed_head}:refs/heads/mixed", cwd=work)
            with self.assertRaisesRegex(ValueError, "allowlisted"):
                release.policy_changes(work, seed, mixed_head)

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


if __name__ == "__main__":
    unittest.main()
