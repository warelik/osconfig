import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release


def policy_signing_workflow_fixture():
    sha = "a" * 40
    return (
        "name: fixture\n"
        "jobs:\n"
        "  sign:\n"
        "    needs: [prepare, build-rpm, review]\n"
        "    if: >-\n"
        "      needs.prepare.outputs.exists == 'true' && needs.build-rpm.result == 'success' &&\n"
        "      needs.review.result == 'success' && needs.review.outputs.ready == 'true'\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 20\n"
        "    permissions:\n"
        "      contents: read\n"
        "    container: fedora:44\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "        with:\n"
            "          ref: ${{ github.sha }}\n"
        "          persist-credentials: false\n"
        "      - run: dnf -y install rpm-sign createrepo_c gnupg2 rpm jq coreutils findutils\n"
        f"      - uses: actions/download-artifact@{sha}\n"
        "        with:\n"
        "          name: google-osconfig-agent-built-rpm\n"
        "          path: ${{ runner.temp }}/osconfig-built\n"
        f"      - run: bash {release.PREFIX}tests/signing.sh \"$RUNNER_TEMP/osconfig-built\"\n"
        "      - name: Sign repository\n"
        "        env:\n"
        "          OSCONFIG_RPM_SIGNING_PRIVATE_KEY: '${{ secrets.OSCONFIG_RPM_SIGNING_PRIVATE_KEY }}'\n"
        "          OSCONFIG_RPM_SIGNING_FINGERPRINT: '${{ vars.OSCONFIG_RPM_SIGNING_FINGERPRINT }}'\n"
        "          EXPECTED_CANDIDATE_SHA: '${{ needs.prepare.outputs.sha }}'\n"
        "          EXPECTED_UPSTREAM_SHA: '${{ needs.prepare.outputs.upstream }}'\n"
        "          EXPECTED_PATCH_SHA: '${{ needs.prepare.outputs.patch }}'\n"
        "        run: |\n"
        f"          bash {release.PREFIX}sign-repo.sh \\\n"
        "            \"$RUNNER_TEMP/osconfig-built\" \"$RUNNER_TEMP/osconfig-pages\"\n"
        f"          bash {release.PREFIX}verify-repo.sh \\\n"
        "            \"$RUNNER_TEMP/osconfig-built\" \"$RUNNER_TEMP/osconfig-pages\"\n"
        f"      - uses: actions/upload-artifact@{sha}\n"
        "        with:\n"
        "          name: google-osconfig-agent-pages\n"
        "          path: ${{ runner.temp }}/osconfig-pages/rpm\n"
        "          if-no-files-found: error\n"
        "          retention-days: 3\n"
    )


class CandidatePolicyCliTests(unittest.TestCase):
    repo = "warelik/osconfig"
    config_sha = "a" * 40
    candidate_sha = "b" * 40

    def run_evidence_cli(self, candidate, run_id):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-cli-") as temporary:
            root = Path(temporary)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            gh = binary_dir / "gh"
            gh.write_text(
                "#!" + sys.executable + "\n"
                "import json, sys\n"
                "path = sys.argv[-1]\n"
                "if path.startswith('repos/warelik/osconfig/actions/runs/123/jobs?'):\n"
                "    print(json.dumps([{'id': 7001, 'run_id': 123, 'name': 'publish', "
                "'status': 'in_progress', 'conclusion': None}]))\n"
                "else:\n"
                "    raise SystemExit('unexpected GitHub API request')\n",
                encoding="utf-8",
            )
            gh.chmod(0o700)
            output = root / "job-evidence.txt"
            env = {
                "PATH": f"{binary_dir}:{os.defpath}",
                "HOME": str(root / "home"),
                "TMPDIR": str(root / "tmp"),
                "GITHUB_REPOSITORY": "warelik/osconfig",
                "PYTHONDONTWRITEBYTECODE": "1",
                "LC_ALL": "C.UTF-8",
            }
            Path(env["HOME"]).mkdir(mode=0o700)
            Path(env["TMPDIR"]).mkdir(mode=0o700)
            result = subprocess.run(
                [sys.executable, "-B", str(candidate), "failed-job-evidence", run_id, str(output)],
                cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False,
            )
            return result, output.read_text(encoding="utf-8") if output.is_file() else None

    def candidate_release(self):
        return Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_RELEASE") or release.__file__).resolve()

    def write_policy_candidate(self, root, requirements):
        candidate = Path(root) / "publisher-policy-candidate"
        patch_dir = candidate / release.PREFIX
        (patch_dir / "tests").mkdir(parents=True)
        (patch_dir / "workflows").mkdir()
        shutil.copy2(self.candidate_release(), patch_dir / "release.py")
        (patch_dir / "tests/test_release.py").write_text("# candidate test fixture\n", encoding="utf-8")
        (patch_dir / "requirements-policy.txt").write_text(requirements, encoding="utf-8")
        (patch_dir / "requirements-policy-bootstrap.txt").write_text(requirements, encoding="utf-8")
        (candidate / release.REPOSITORY_CONF).parent.mkdir(parents=True, exist_ok=True)
        (candidate / release.REPOSITORY_CONF).write_text("# candidate config fixture\n", encoding="utf-8")
        (patch_dir / "workflows/google-osconfig-agent-inventory.yml").write_text(
            policy_signing_workflow_fixture(),
            encoding="utf-8",
        )
        return candidate

    def policy_pull(self, config=None, head=None, number=42):
        config = config or self.config_sha
        head = head or self.candidate_sha
        identity = json.dumps({"schema": 1, "config": config, "seed": config}, sort_keys=True)
        return {
            "number": number,
            "state": "open",
            "user": {"login": "warelik", "type": "User"},
            "body": f"<!-- osconfig-policy-repair:v1 {identity} -->",
            "base": {"ref": "master", "sha": config,
                     "repo": {"full_name": self.repo}},
            "head": {"ref": "repair/osconfig-policy-fixture",
                     "sha": head, "repo": {"full_name": self.repo}},
        }

    def owner_review_request(self, head=None, *, created_at="2026-10-17T00:00:00Z"):
        head = head or self.candidate_sha
        return {
            "user": {"login": "warelik", "type": "User"},
            "created_at": created_at,
            "body": f"@codex review\n<!-- osconfig-policy-codex:{head} -->",
        }

    def codex_review(self, head=None, *, body="Codex Review: Didn't find any major issues."):
        return {
            "user": {"login": "chatgpt-codex-connector[bot]", "type": "Bot"},
            "commit_id": head or self.candidate_sha,
            "submitted_at": "2026-10-17T00:05:00Z",
            "state": "COMMENTED",
            "body": body,
        }

    def policy_routes(self, pull, *, comments=None, reviews=None, inline=None, master_sha=None):
        number = pull["number"]
        routes = {
            f"GET repos/{self.repo}/pulls/{number}": pull,
            f"GET repos/{self.repo}/issues/{number}/comments": comments or [],
            f"GET repos/{self.repo}/pulls/{number}/reviews": reviews or [],
            f"GET repos/{self.repo}/pulls/{number}/comments": inline or [],
            "GET user": {"login": "warelik", "type": "User"},
        }
        if master_sha:
            routes[f"GET repos/{self.repo}/commits/master"] = {"sha": master_sha}
        return routes

    def application_review_fixtures(self, *, manifest_sha=None, pull_sha=None, review_body=None):
        upstream = "d" * 40
        manifest_sha = manifest_sha or self.candidate_sha
        pull_sha = pull_sha or manifest_sha
        branch = "review/osconfig-fixture"
        pull = {
            "number": 73,
            "state": "open",
            "base": {"ref": f"review-base/{upstream}", "sha": upstream,
                     "repo": {"full_name": self.repo}},
            "head": {"ref": branch, "sha": pull_sha,
                     "repo": {"full_name": self.repo}},
        }
        manifest = {
            "candidatePr": 73,
            "candidateSha": manifest_sha,
            "upstreamCommit": upstream,
            "candidateBranch": branch,
        }
        comments = [{
            "user": {"login": "warelik", "type": "User"},
            "created_at": "2026-10-17T00:00:00Z",
            "body": f"@codex review\n<!-- osconfig-codex:{manifest_sha} -->",
        }]
        review = self.codex_review(
            manifest_sha,
            body=review_body or "Codex Review: Didn't find any major issues.",
        )
        routes = {
            f"GET repos/{self.repo}/pulls/73": pull,
            f"GET repos/{self.repo}/issues/73/comments": comments,
            f"GET repos/{self.repo}/pulls/73/reviews": [review],
            f"GET repos/{self.repo}/pulls/73/comments": [],
        }
        return manifest, routes

    def run_application_review(self, root, *, manifest_sha=None, pull_sha=None, review_body=None):
        candidate_dir = root / "application-candidate"
        candidate_dir.mkdir()
        manifest, routes = self.application_review_fixtures(
            manifest_sha=manifest_sha, pull_sha=pull_sha, review_body=review_body,
        )
        (candidate_dir / "candidate-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8",
        )
        return self.run_candidate_cli(
            root, self.candidate_release(), ["review", candidate_dir], routes=routes,
        )

    def run_candidate_cli(self, root, candidate, arguments, *, routes,
                          git_mode=None, changed_paths="", env_extra=None,
                          container_mode=None):
        root = Path(root)
        binary_dir = root / "bin"
        binary_dir.mkdir(parents=True, exist_ok=True)
        gh = binary_dir / "gh"
        gh.write_text(
            "#!" + sys.executable + "\n" + r'''import json, os, sys
args = sys.argv[1:]
if args[:2] == ["auth", "setup-git"]:
    raise SystemExit(0)
if not args or args[0] != "api":
    print("unexpected fake gh command", file=sys.stderr)
    raise SystemExit(2)
method = "GET"
if "--method" in args:
    method = args[args.index("--method") + 1]
path = next(arg for arg in args[1:]
            if not arg.startswith("-") and arg not in {"GET", "POST", "PATCH", "PUT", "DELETE"})
body = sys.stdin.read() if "--input" in args else ""
try:
    payload = json.loads(body) if body else None
except ValueError:
    payload = body
entry = {"method": method, "path": path, "body": payload}
with open(os.environ["OSCONFIG_FAKE_GH_CALLS"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(entry, sort_keys=True) + "\n")
routes = json.load(open(os.environ["OSCONFIG_FAKE_GH_ROUTES"], encoding="utf-8"))
base_path = path.split("?per_page=", 1)[0]
keys = (f"{method} {path}", f"{method} {base_path}")
found = next((key for key in keys if key in routes), None)
if found is not None:
    response = routes[found]
elif method == "GET" and base_path.startswith("repos/warelik/osconfig/commits/"):
    response = {"sha": base_path.rsplit("/", 1)[-1]}
elif method == "GET" and base_path.startswith("repos/actions/") and "/commits/" in base_path:
    response = {"sha": base_path.rsplit("/", 1)[-1]}
else:
    print("unexpected fake GitHub API request: " + method + " " + path, file=sys.stderr)
    raise SystemExit(2)
print(json.dumps(response))
''',
            encoding="utf-8",
        )
        gh.chmod(0o700)
        routes_file = root / "github-routes.json"
        routes_file.write_text(json.dumps(routes), encoding="utf-8")
        calls_file = root / "github-calls.jsonl"
        calls_file.touch()
        if container_mode:
            docker = binary_dir / "docker"
            docker.write_text(
                "#!" + sys.executable + "\n" + r'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["info"]:
    raise SystemExit(0)
if args[:1] == ["run"] and "download" in args:
    requirement_path = Path(args[args.index("-r") + 1])
    if "PyYAML==6.0.3" in requirement_path.read_text(encoding="utf-8"):
        print("ERROR: Downloaded PyYAML wheel does not match the required SHA-256", file=sys.stderr)
    else:
        print("ERROR: No matching distribution found for PyYAML==999999.0.0", file=sys.stderr)
    raise SystemExit(1)
print("unexpected fake container command", file=sys.stderr)
raise SystemExit(2)
''',
                encoding="utf-8",
            )
            docker.chmod(0o700)
        fake_git = None
        if git_mode:
            fake_git = binary_dir / "git"
            fake_git.write_text(
                "#!" + sys.executable + "\n" + r'''import json, os, sys
args = sys.argv[1:]
mode = os.environ["OSCONFIG_FAKE_GIT_MODE"]
with open(os.environ["OSCONFIG_FAKE_GIT_CALLS"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")
if mode == "scope":
    if args == ["rev-parse", "--is-shallow-repository"]:
        print("false")
        raise SystemExit(0)
    if args and args[0] in {"fetch", "merge-base"}:
        raise SystemExit(0)
    if args and args[0] == "diff" and "--name-only" in args:
        sys.stdout.write(os.environ.get("OSCONFIG_FAKE_CHANGED_PATHS", ""))
        raise SystemExit(0)
    if args and args[0] == "ls-tree":
        print("100644 blob " + "a" * 40 + "\\tfixture")
        raise SystemExit(0)
    print("unexpected scoped fake git command", file=sys.stderr)
    raise SystemExit(2)
if mode == "rewrite-clone":
    if args and args[0] == "clone":
        remote = os.environ["OSCONFIG_GIT_REMOTE"]
        args = [remote if arg == "https://github.com/warelik/osconfig.git" else arg for arg in args]
    os.execv(os.environ["OSCONFIG_REAL_GIT"], [os.environ["OSCONFIG_REAL_GIT"], *args])
print("unexpected fake git mode", file=sys.stderr)
raise SystemExit(2)
''',
                encoding="utf-8",
            )
            fake_git.chmod(0o700)
        home, tmp = root / "home", root / "tmp"
        home.mkdir(mode=0o700, exist_ok=True)
        tmp.mkdir(mode=0o700, exist_ok=True)
        output_file = root / "github-output"
        output_file.touch()
        env = {
            "PATH": f"{binary_dir}:{os.defpath}",
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "GITHUB_REPOSITORY": self.repo,
            "GITHUB_OUTPUT": str(output_file),
            "CODEX_REQUEST_TOKEN": "fixture-owner-token",
            "PYTHONDONTWRITEBYTECODE": "1",
            # Native policy checks install their trusted parser outside site-packages.
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "OSCONFIG_FAKE_GH_ROUTES": str(routes_file),
            "OSCONFIG_FAKE_GH_CALLS": str(calls_file),
        }
        if container_mode:
            env.update(PATH=str(binary_dir), OSCONFIG_FAKE_CONTAINER_MODE=container_mode)
        if git_mode:
            git_calls = root / "git-calls.jsonl"
            git_calls.touch()
            env.update(OSCONFIG_FAKE_GIT_MODE=git_mode,
                       OSCONFIG_FAKE_GIT_CALLS=str(git_calls),
                       OSCONFIG_FAKE_CHANGED_PATHS=changed_paths,
                       OSCONFIG_REAL_GIT=shutil.which("git") or "/usr/bin/git")
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, "-B", str(candidate), *map(str, arguments)],
            cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
        gh_calls = [json.loads(line) for line in calls_file.read_text(encoding="utf-8").splitlines()]
        git_call_file = root / "git-calls.jsonl"
        git_calls = ([json.loads(line) for line in git_call_file.read_text(encoding="utf-8").splitlines()]
                     if git_call_file.exists() else [])
        return result, output_file.read_text(encoding="utf-8"), gh_calls, git_calls

    def test_policy_review_cli_accepts_clean_review_for_requested_exact_sha(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-review-clean-") as temporary:
            root = Path(temporary)
            pull = self.policy_pull()
            routes = self.policy_routes(
                pull,
                comments=[self.owner_review_request()],
                reviews=[self.codex_review()],
            )
            result, output, calls, _ = self.run_candidate_cli(
                root, self.candidate_release(), ["policy-review", root], routes=routes,
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": self.candidate_sha},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("policy_review_ready=true", output)
        self.assertIn(f"policy_head={self.candidate_sha}", output)
        self.assertFalse(any(call["method"] == "POST" for call in calls))

    def test_policy_review_cli_rejects_an_exact_sha_finding(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-review-finding-") as temporary:
            root = Path(temporary)
            pull = self.policy_pull()
            routes = self.policy_routes(
                pull,
                comments=[self.owner_review_request()],
                reviews=[self.codex_review(body="Codex Review: [P1] unresolved defect")],
            )
            result, output, _, _ = self.run_candidate_cli(
                root, self.candidate_release(), ["policy-review", root], routes=routes,
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": self.candidate_sha},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("policy_review_ready=false", output)
        self.assertIn("Codex reported a finding on this exact SHA", output)

    def test_policy_review_cli_rejects_stale_expected_sha_before_requesting_review(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-review-stale-") as temporary:
            root = Path(temporary)
            pull = self.policy_pull()
            routes = self.policy_routes(pull)
            result, output, calls, _ = self.run_candidate_cli(
                root, self.candidate_release(), ["policy-review", root], routes=routes,
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": "c" * 40},
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("changed after isolated checks", result.stderr)
        self.assertEqual(output, "")
        self.assertFalse(any(call["method"] == "POST" for call in calls))

    def test_application_review_cli_accepts_clean_review_for_manifest_exact_sha(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-app-review-clean-") as temporary:
            result, output, _, _ = self.run_application_review(Path(temporary))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review_ready=true", output)
        self.assertIn("Completed exact-SHA Codex PR review", output)

    def test_application_review_cli_rejects_a_stale_candidate_head(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-app-review-stale-") as temporary:
            result, output, _, _ = self.run_application_review(
                Path(temporary), pull_sha="c" * 40,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review_ready=false", output)
        self.assertIn("Candidate PR head or exact upstream base changed", output)

    def test_application_review_cli_rejects_a_real_exact_sha_finding(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-app-review-finding-") as temporary:
            result, output, _, _ = self.run_application_review(
                Path(temporary), review_body="Codex Review: [P1] unresolved inventory defect",
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review_ready=false", output)
        self.assertIn("Codex reported a finding on this exact SHA", output)

    def assert_policy_candidate_source_cleanup(self, *, fail_at_delta=False):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-source-test-") as temporary:
            candidate_dir = Path(temporary) / "candidate"
            candidate_dir.mkdir()
            pull = self.policy_pull()
            candidate = {
                "schema": 1, "repository": self.repo,
                "upstream_sha": "d" * 40, "application_sha": "e" * 40,
                "configuration_sha": "f" * 40, "patchset_sha256": "1" * 64,
                "recipe_sha256": "2" * 64, "platform": "fedora-44/x86_64",
            }
            published = {
                "upstreamTag": "v1.2.3", "upstreamArchiveSha256": "3" * 64,
                "patchSha256": "4" * 64, "specSha256": "5" * 64,
            }
            settings = {"github_owner": "warelik", "github_repo": "osconfig",
                        "signing_fingerprint": "A1B2C3D4"}
            source_roots = []
            real_temporary_directory = release.tempfile.TemporaryDirectory

            def tracked_temporary_directory(*args, **kwargs):
                manager = real_temporary_directory(*args, **kwargs)
                source_roots.append(Path(manager.name))
                return manager

            def api(path, **_kwargs):
                if path == f"repos/{self.repo}/pulls/42":
                    return pull
                if path == f"repos/{self.repo}/actions/variables/FORK_ACCEPTED_BASELINE":
                    return {"name": "FORK_ACCEPTED_BASELINE", "value": "{}"}
                raise AssertionError(path)

            def candidate_identity(value):
                canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
                return release.hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            def published_identity(_repo, _published, work_root):
                work_root = Path(work_root)
                self.assertTrue(work_root.is_dir())
                (work_root / "source-fixture").write_text("temporary checkout", encoding="utf-8")
                (work_root / "published-baseline-source").mkdir()
                return dict(candidate)

            def create_delta(*_args, **_kwargs):
                if fail_at_delta:
                    raise RuntimeError("fixture delta snapshot failed")
                return "6" * 40, f"review-base/{candidate['configuration_sha']}"

            ensure_pull = iter(({"number": 71}, {"number": 72}))
            review_result = ({}, {}, {"state": "ready", "complete": True})
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {
                    "GITHUB_REPOSITORY": self.repo,
                    "GITHUB_SHA": self.config_sha,
                    "POLICY_PR_NUMBER": "42",
                    "POLICY_HEAD_SHA": self.candidate_sha,
                    "OSCONFIG_RPM_SIGNING_FINGERPRINT": settings["signing_fingerprint"],
                }, clear=True))
                stack.enter_context(patch.object(
                    release.tempfile, "TemporaryDirectory",
                    side_effect=tracked_temporary_directory))
                stack.enter_context(patch.object(release, "api", side_effect=api))
                stack.enter_context(patch.object(
                    release, "policy_changes", return_value=[release.PREFIX + "release.py"]))
                stack.enter_context(patch.object(release, "repository_settings", return_value=settings))
                stack.enter_context(patch.object(release, "published_manifest", return_value=published))
                stack.enter_context(patch.object(
                    release, "owner_token", return_value="fixture-owner-token"))
                stack.enter_context(patch.object(release, "lifecycle_module", return_value=type(
                    "LifecycleFixture", (), {"candidate_identity": staticmethod(candidate_identity)})()))
                stack.enter_context(patch.object(
                    release, "verified_pages_baseline",
                    return_value={"published_at": "2026-10-01T00:00:00Z"}))
                stack.enter_context(patch.object(
                    release, "published_candidate_identity", side_effect=published_identity))
                stack.enter_context(patch.object(
                    release, "accepted_baseline_proof", return_value={"fixture": True}))
                stack.enter_context(patch.object(release, "run", return_value=""))
                stack.enter_context(patch.object(release, "ensure_review_base"))
                stack.enter_context(patch.object(
                    release, "create_delta_snapshot", side_effect=create_delta))
                stack.enter_context(patch.object(
                    release, "create_application_review_context", return_value="7" * 40))
                stack.enter_context(patch.object(release, "ensure_review_branch"))
                stack.enter_context(patch.object(
                    release, "ensure_review_pull",
                    side_effect=lambda *_args, **_kwargs: next(ensure_pull)))
                stack.enter_context(patch.object(
                    release, "load_review_finding_history", return_value=([], [], {}, {})))
                stack.enter_context(patch.object(
                    release, "create_review_finding_dispositions"))
                stack.enter_context(patch.object(release, "record_policy_pair_context"))
                stack.enter_context(patch.object(release, "request_lifecycle_review"))
                stack.enter_context(patch.object(
                    release, "review_pair_status", return_value=review_result))
                stack.enter_context(patch.object(
                    release, "complete_machine_finding_dispositions",
                    return_value=review_result))
                stack.enter_context(patch.object(release, "record_review_finding_batch"))
                stack.enter_context(patch.object(release, "output"))
                if fail_at_delta:
                    with self.assertRaisesRegex(RuntimeError, "fixture delta snapshot failed"):
                        release.prepare_policy_candidate(candidate_dir)
                else:
                    release.prepare_policy_candidate(candidate_dir)

            self.assertEqual(len(source_roots), 1)
            self.assertFalse(source_roots[0].exists())
            self.assertEqual((candidate_dir / "inputs" / "candidate-manifest.json").is_file(),
                             not fail_at_delta)

    def test_prepare_policy_candidate_removes_temporary_source_after_success(self):
        self.assert_policy_candidate_source_cleanup()

    def test_prepare_policy_candidate_removes_temporary_source_after_failure(self):
        self.assert_policy_candidate_source_cleanup(fail_at_delta=True)

    def policy_repair_history(self, head, *, created_at, started_at):
        old = int(datetime.now(timezone.utc).timestamp()) - 10800
        state = json.dumps({"config": self.config_sha, "startedAt": started_at}, sort_keys=True)
        return [{
            "user": {"login": "warelik", "type": "User"},
            "created_at": created_at,
            "html_url": "https://github.com/warelik/osconfig/pull/42#issuecomment-old",
            "body": (f"<!-- osconfig-policy-cycle:v1 {state} -->\n"
                     f"<!-- osconfig-policy-attempt:v1 1 -->\n"
                     f"<!-- osconfig-policy-fix:v1 {head} {old} -->"),
        }]

    def run_policy_repair(self, root, *, created_at):
        pull = self.policy_pull()
        routes = self.policy_routes(
            pull,
            comments=self.policy_repair_history(
                self.candidate_sha, created_at=created_at,
                started_at="2026-10-15T06:00:00+00:00",
            ),
        )
        routes[f"POST repos/{self.repo}/issues/42/comments"] = None
        evidence = root / "failure.txt"
        evidence.write_text("isolated publisher regression failed", encoding="utf-8")
        return self.run_candidate_cli(
            root, self.candidate_release(),
            ["repair-policy-pr", "42", self.candidate_sha, evidence], routes=routes,
        )

    def test_policy_repair_cli_continues_after_window_and_preserves_history(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-repair-due-") as temporary:
            root = Path(temporary)
            created = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
            result, _, calls, _ = self.run_policy_repair(root, created_at=created)
        self.assertEqual(result.returncode, 0, result.stderr)
        posts = [call for call in calls if call["method"] == "POST"]
        self.assertEqual(len(posts), 1)
        body = posts[0]["body"]["body"]
        self.assertIn("Attempt 2", body)
        self.assertIn("Repair cycle began: 2026-10-15T06:00:00+00:00", body)
        self.assertIn("isolated publisher regression failed", body)
        self.assertIn(f"<!-- osconfig-policy-fix:v1 {self.candidate_sha} ", body)

    def test_policy_repair_cli_does_not_duplicate_task_inside_active_window(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-repair-active-") as temporary:
            root = Path(temporary)
            created = datetime.now(timezone.utc).isoformat()
            result, _, calls, _ = self.run_policy_repair(root, created_at=created)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Publisher repair task is active on PR #42", result.stdout)
        self.assertFalse(any(call["method"] == "POST" for call in calls))

    def test_policy_check_cli_accepts_unchanged_exact_candidate(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-scope-clean-") as temporary:
            root = Path(temporary)
            candidate = root / "candidate-repo"
            candidate.mkdir()
            pull = self.policy_pull()
            routes = self.policy_routes(pull)
            result, output, _, git_calls = self.run_candidate_cli(
                root, self.candidate_release(), ["policy-check", candidate], routes=routes,
                git_mode="scope",
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": self.candidate_sha},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("policy_candidate_changed=false", output)
        self.assertTrue(any(call and call[0] == "diff" for call in git_calls))

    def test_policy_check_cli_rejects_out_of_scope_change(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-scope-deny-") as temporary:
            root = Path(temporary)
            candidate = root / "candidate-repo"
            candidate.mkdir()
            pull = self.policy_pull()
            routes = self.policy_routes(pull)
            result, output, _, _ = self.run_candidate_cli(
                root, self.candidate_release(), ["policy-check", candidate], routes=routes,
                git_mode="scope", changed_paths=".vps/google-osconfig-agent/repository.conf\n",
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": self.candidate_sha},
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("allowlisted policy files", result.stderr)
        self.assertEqual(output, "")

    def test_policy_check_cli_does_not_mark_malformed_parser_requirements_changed(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-requirements-malformed-") as temporary:
            root = Path(temporary)
            candidate = self.write_policy_candidate(root, "not a valid requirement\n")
            result, output, calls, git_calls = self.run_candidate_cli(
                root, candidate / release.PREFIX / "release.py", ["policy-check", candidate],
                routes=self.policy_routes(self.policy_pull()), git_mode="scope",
                changed_paths=release.PREFIX + "requirements-policy.txt\n",
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": self.candidate_sha},
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Publisher parser requirements", result.stderr)
        self.assertEqual(output, "")
        self.assertFalse(any(call["path"].startswith("repos/actions/") for call in calls))
        self.assertTrue(any(call and call[0] == "diff" for call in git_calls))

    def test_policy_check_cli_rejects_mismatched_bootstrap_pin_before_candidate_tests(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-requirements-mismatch-") as temporary:
            root = Path(temporary)
            candidate = self.write_policy_candidate(
                root, f"PyYAML==6.0.3 --hash=sha256:{'a' * 64}\n",
            )
            (candidate / release.PREFIX / "requirements-policy-bootstrap.txt").write_text(
                f"PyYAML==6.0.3 --hash=sha256:{'b' * 64}\n", encoding="utf-8",
            )
            changed = (release.PREFIX + "requirements-policy.txt\n"
                       + release.PREFIX + "requirements-policy-bootstrap.txt\n")
            result, output, calls, git_calls = self.run_candidate_cli(
                root, candidate / release.PREFIX / "release.py", ["policy-check", candidate],
                routes=self.policy_routes(self.policy_pull()), git_mode="scope",
                changed_paths=changed,
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": self.candidate_sha},
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("same exact pin and hash", result.stderr)
        self.assertEqual(output, "")
        self.assertFalse(any(call["method"] == "POST" for call in calls))
        self.assertTrue(any(call and call[0] == "diff" for call in git_calls))

    def test_policy_check_cli_does_not_mark_unavailable_parser_wheel_changed(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-requirements-missing-") as temporary:
            root = Path(temporary)
            candidate = self.write_policy_candidate(
                root, f"PyYAML==999999.0.0 --hash=sha256:{'b' * 64}\n",
            )
            action_sha = "a" * 40
            routes = self.policy_routes(self.policy_pull())
            routes[f"GET repos/actions/checkout/commits/{action_sha}"] = {"sha": action_sha}
            result, output, calls, git_calls = self.run_candidate_cli(
                root, candidate / release.PREFIX / "release.py", ["policy-check", candidate], routes=routes,
                git_mode="scope",
                changed_paths=release.PREFIX + "requirements-policy.txt\n",
                env_extra={
                    "POLICY_PR_NUMBER": "42",
                    "POLICY_HEAD_SHA": self.candidate_sha,
                    "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                },
                container_mode="missing-parser-wheel",
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Official PyYAML wheel resolution failed", result.stderr)
        self.assertIn("No matching distribution", result.stderr)
        self.assertEqual(output, "")
        self.assertFalse(any(call["method"] == "POST" for call in calls))
        self.assertTrue(any(call and call[0] == "diff" for call in git_calls))

    def test_policy_check_cli_does_not_mark_a_mismatched_parser_wheel_hash_changed(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-requirements-hash-") as temporary:
            root = Path(temporary)
            candidate = self.write_policy_candidate(
                root, f"PyYAML==6.0.3 --hash=sha256:{'b' * 64}\n",
            )
            routes = self.policy_routes(self.policy_pull())
            result, output, calls, git_calls = self.run_candidate_cli(
                root, candidate / release.PREFIX / "release.py", ["policy-check", candidate], routes=routes,
                git_mode="scope",
                changed_paths=release.PREFIX + "requirements-policy.txt\n",
                env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": self.candidate_sha},
                container_mode="bad-parser-hash",
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Official PyYAML wheel resolution failed", result.stderr)
        self.assertIn("does not match the required SHA-256", result.stderr)
        self.assertEqual(output, "")
        self.assertFalse(any(call["method"] == "POST" for call in calls))
        self.assertTrue(any(call and call[0] == "diff" for call in git_calls))

    def git(self, *arguments, cwd):
        result = subprocess.run(["git", *map(str, arguments)], cwd=cwd, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout.strip()

    def adoption_fixture(self, root):
        remote = root / "origin.git"
        seed = root / "seed"
        self.git("init", "--bare", "--initial-branch=master", remote, cwd=root)
        self.git("init", "--initial-branch=master", seed, cwd=root)
        self.git("config", "user.name", "GOS policy fixture", cwd=seed)
        self.git("config", "user.email", "gos-policy-fixture@example.invalid", cwd=seed)
        base_files = {
            release.PREFIX + "release.py": "trusted base policy\n",
            release.PREFIX + "tests/test_release.py": "trusted unit baseline\n",
            release.PREFIX + "tests/test_policy_isolation.py": "trusted immutable CLI tests\n",
            release.PREFIX + "workflows/google-osconfig-agent-inventory.yml": "name: fixture\n",
            ".github/workflows/google-osconfig-agent-inventory.yml": "name: fixture\n",
            "README.md": "unrelated tracked file\n",
        }
        for relative, content in base_files.items():
            path = seed / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.git("add", "--all", cwd=seed)
        self.git("commit", "-m", "trusted fixture base", cwd=seed)
        base_sha = self.git("rev-parse", "HEAD", cwd=seed)
        self.git("remote", "add", "origin", remote, cwd=seed)
        self.git("push", "origin", "HEAD:refs/heads/master", cwd=seed)

        candidate = root / "candidate-repo"
        self.git("clone", remote, candidate, cwd=root)
        self.git("config", "user.name", "GOS candidate fixture", cwd=candidate)
        self.git("config", "user.email", "gos-candidate-fixture@example.invalid", cwd=candidate)
        self.git("checkout", "-b", "repair/osconfig-policy-fixture", cwd=candidate)
        release_file = candidate / (release.PREFIX + "release.py")
        isolation_test = candidate / (release.PREFIX + "tests/test_policy_isolation.py")
        release_file.write_text("reviewed proposed policy\n", encoding="utf-8")
        isolation_test.write_text("reviewed trusted CLI regression update\n", encoding="utf-8")
        self.git("add", "--", release.PREFIX + "release.py",
                 release.PREFIX + "tests/test_policy_isolation.py", cwd=candidate)
        self.git("commit", "-m", "fixture proposal", cwd=candidate)
        head_sha = self.git("rev-parse", "HEAD", cwd=candidate)
        self.git("push", "origin", f"{head_sha}:refs/heads/repair/osconfig-policy-fixture", cwd=candidate)
        return remote, candidate, base_sha, head_sha

    def run_adopt_policy(self, root, *, finding=False):
        remote, candidate, base_sha, head_sha = self.adoption_fixture(root)
        pull = self.policy_pull(config=base_sha, head=head_sha)
        comments = [self.owner_review_request(head_sha)]
        review_body = "Codex Review: [P1] unresolved policy finding" if finding else "Codex Review: Didn't find any major issues."
        routes = self.policy_routes(
            pull, comments=comments, reviews=[self.codex_review(head_sha, body=review_body)],
            master_sha=base_sha,
        )
        routes[f"POST repos/{self.repo}/issues/42/comments"] = None
        routes[f"PATCH repos/{self.repo}/pulls/42"] = None
        routes[f"POST repos/{self.repo}/actions/workflows/google-osconfig-agent-inventory.yml/dispatches"] = None
        result, output, calls, git_calls = self.run_candidate_cli(
            root, self.candidate_release(), ["adopt-policy", candidate], routes=routes,
            git_mode="rewrite-clone",
            env_extra={"POLICY_PR_NUMBER": "42", "POLICY_HEAD_SHA": head_sha,
                       "OSCONFIG_GIT_REMOTE": remote.as_uri()},
        )
        return result, output, calls, git_calls, remote, candidate, base_sha, head_sha

    def test_adopt_policy_cli_selectively_applies_reviewed_paths_to_trusted_base(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-adopt-positive-") as temporary:
            (result, output, calls, git_calls, remote, _, base_sha, head_sha) = self.run_adopt_policy(
                Path(temporary))
            master_sha = self.git("--git-dir", remote, "rev-parse", "refs/heads/master", cwd=temporary)
            parents = self.git("--git-dir", remote, "show", "-s", "--format=%P", master_sha, cwd=temporary)
            changed = self.git("--git-dir", remote, "diff-tree", "--no-commit-id", "--name-only",
                               "-r", base_sha, master_sha, cwd=temporary).splitlines()
            release_value = self.git("--git-dir", remote, "show",
                                     f"{master_sha}:{release.PREFIX}release.py", cwd=temporary)
            isolated_test_value = self.git("--git-dir", remote, "show",
                                           f"{master_sha}:{release.PREFIX}tests/test_policy_isolation.py",
                                           cwd=temporary)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Selectively adopted reviewed publisher policy", result.stdout)
        self.assertNotEqual(master_sha, head_sha)
        self.assertEqual(parents, base_sha)
        self.assertEqual(sorted(changed), sorted([
            release.PREFIX + "release.py",
            release.PREFIX + "tests/test_policy_isolation.py",
        ]))
        self.assertEqual(release_value, "reviewed proposed policy")
        self.assertEqual(isolated_test_value, "reviewed trusted CLI regression update")
        self.assertTrue(any(call["method"] == "PATCH" for call in calls))
        self.assertTrue(any(call["method"] == "POST" and "dispatches" in call["path"] for call in calls))
        self.assertTrue(any(call and call[0] == "apply" for call in git_calls))

    def test_adopt_policy_cli_does_not_apply_a_review_with_findings(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-adopt-finding-") as temporary:
            result, _, calls, _, remote, _, base_sha, _ = self.run_adopt_policy(
                Path(temporary), finding=True)
            master_sha = self.git("--git-dir", remote, "rev-parse", "refs/heads/master", cwd=temporary)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Codex reported a finding on this exact SHA", result.stderr)
        self.assertEqual(master_sha, base_sha)
        self.assertFalse(any(call["method"] == "POST" and "dispatches" in call["path"] for call in calls))

    def test_candidate_cli_produces_required_run_and_job_evidence(self):
        candidate = Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_RELEASE") or release.__file__).resolve()
        result, evidence = self.run_evidence_cli(candidate, "123")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(evidence, "candidate CLI exited successfully without writing required evidence")
        self.assertIn("No completed failed jobs are available yet", evidence)
        self.assertIn("https://github.com/warelik/osconfig/actions/runs/123", evidence)
        self.assertIn("publish: status=in_progress", evidence)

    def test_candidate_cli_rejects_invalid_run_identity(self):
        candidate = Path(os.environ.get("OSCONFIG_POLICY_CANDIDATE_RELEASE") or release.__file__).resolve()
        result, evidence = self.run_evidence_cli(candidate, "not-a-run-id")
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(evidence, "candidate CLI wrote evidence for an invalid run identity")

    def test_top_level_early_exit_cannot_satisfy_the_required_cli_effect(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-exit-") as temporary:
            candidate = Path(temporary) / "release.py"
            candidate.write_text("import os\nos._exit(0)\n", encoding="utf-8")
            result, evidence = self.run_evidence_cli(candidate, "123")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(evidence, "early exit forged the required evidence file")


class PolicyGateIsolationTests(unittest.TestCase):
    def test_candidate_cannot_modify_or_replace_the_oracle_parser(self):
        if not os.environ.get("OSCONFIG_POLICY_CANDIDATE_RELEASE"):
            self.skipTest("requires the actual isolated policy-check container")
        import errno
        parser = Path(os.environ["PYTHONPATH"]) / "yaml" / "__init__.py"
        self.assertTrue(parser.is_file())
        for target in (parser, parser.parent / ".oracle-write-probe"):
            try:
                with target.open("ab") as stream:
                    stream.write(b"\n# unexpected writable oracle dependency\n")
            except OSError as error:
                self.assertIn(error.errno, (errno.EROFS, errno.EACCES, errno.EPERM))
            else:
                self.fail("candidate can modify or replace its oracle parser dependency")

    def actionlint_archive(self):
        import io
        import tarfile

        payload = b"#!/bin/sh\nexit 0\n"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("actionlint")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        return stream.getvalue()

    def test_pre_adoption_gate_does_not_execute_candidate_python(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-isolation-") as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            candidate = root / "candidate"
            marker = root / "candidate-executed"
            trusted_tests = trusted / release.PREFIX / "tests"
            candidate_tests = candidate / release.PREFIX / "tests"
            trusted_tests.mkdir(parents=True)
            candidate_tests.mkdir(parents=True)
            (candidate / release.PREFIX / "requirements-policy.txt").write_text(
                "PyYAML==6.0.3 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8",
            )
            (candidate / release.PREFIX / "requirements-policy-bootstrap.txt").write_text(
                "PyYAML==6.0.3 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8",
            )
            (trusted / release.PREFIX / "release.py").write_text("# trusted fixture\n", encoding="utf-8")
            (trusted_tests / "test_release.py").write_text("# trusted test fixture\n", encoding="utf-8")
            (trusted_tests / "test_policy_isolation.py").write_text("# trusted isolation fixture\n", encoding="utf-8")
            (trusted / release.REPOSITORY_CONF).parent.mkdir(parents=True, exist_ok=True)
            (trusted / release.REPOSITORY_CONF).write_text("# trusted configuration fixture\n", encoding="utf-8")
            proposal = "from pathlib import Path\nPath({!r}).write_text('executed')\n".format(str(marker))
            (candidate / release.PREFIX / "release.py").write_text(proposal, encoding="utf-8")
            (candidate_tests / "test_release.py").write_text(proposal, encoding="utf-8")
            workflow = candidate / release.PREFIX / "workflows/google-osconfig-agent-inventory.yml"
            installed = candidate / ".github/workflows/google-osconfig-agent-inventory.yml"
            workflow.parent.mkdir(parents=True)
            installed.parent.mkdir(parents=True)
            workflow.write_text(policy_signing_workflow_fixture(), encoding="utf-8")
            installed.write_bytes(workflow.read_bytes())

            archive = self.actionlint_archive()
            commands = []
            container_host_environments = []
            requested_requirements = []

            def completed(command, **kwargs):
                commands.append(command)
                if command and command[0].endswith("/docker") and command[1] == "run":
                    container_host_environments.append(kwargs["env"])
                    if "download" in command:
                        requirements_path = Path(command[command.index("-r") + 1])
                        requested_requirements.append(requirements_path.read_text(encoding="utf-8"))
                        destination = Path(command[command.index("--dest") + 1])
                        destination.mkdir(parents=True, exist_ok=True)
                        (destination / "pyyaml-6.0.3-py3-none-any.whl").write_bytes(b"fixture wheel")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(release, "ROOT", trusted), \
                 patch.object(release, "api", return_value={"sha": "a" * 40}), \
                 patch.object(release, "ACTIONLINT_SHA256", __import__("hashlib").sha256(archive).hexdigest()), \
                 patch.object(release, "urlopen", return_value=__import__("io").BytesIO(archive)), \
                 patch.object(release.shutil, "which",
                              side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None), \
                 patch.object(release.subprocess, "run", side_effect=completed):
                release.check_policy(candidate)

            self.assertFalse(marker.exists())
            docker_commands = [command for command in commands
                               if command[0].endswith("/docker") and command[1] == "run"]
            self.assertEqual(len(docker_commands), 3)
            self.assertEqual(len(container_host_environments), 3)
            for host_environment in container_host_environments:
                self.assertEqual(host_environment.get("HOME"), os.environ.get("HOME"))
                self.assertEqual(host_environment.get("XDG_DATA_HOME"), os.environ.get("XDG_DATA_HOME"))
            for command in docker_commands:
                mount_specs = [command[index + 1] for index, value in enumerate(command[:-1])
                               if value == "--mount"]
                self.assertFalse(any(spec.startswith(f"type=bind,source={candidate},")
                                    or f",source={candidate}/" in spec
                                    for spec in mount_specs))
                self.assertNotIn(str(candidate / release.PREFIX / "release.py"), [
                    argument for argument in command
                    if not argument.startswith("OSCONFIG_POLICY_CANDIDATE_RELEASE=")
                ])
            download = next(command for command in docker_commands if "download" in command)
            self.assertIn("https://pypi.org/simple", download)
            self.assertIn("--only-binary=:all:", download)
            self.assertIn("--require-hashes", download)
            self.assertEqual(len(requested_requirements), 1)
            proposed_requirements = requested_requirements[0]
            self.assertIn("PyYAML==6.0.3", proposed_requirements)
            self.assertIn("--hash=sha256:", proposed_requirements)
            install = next(command for command in docker_commands if "install" in command)
            self.assertIn("--no-index", install)
            self.assertIn("--network=none", install)
            test_run = next(command for command in docker_commands if "-c" in command)
            self.assertIn("--network=none", test_run)
            self.assertTrue(any(value.startswith("PYTHONPATH=") for value in test_run))
            parser_path = next(value.split("=", 1)[1] for value in test_run
                               if value.startswith("PYTHONPATH="))
            protected_parser = f"type=bind,source={parser_path},target={parser_path},readonly"
            writable_parent = str(Path(parser_path).parent)
            writable_mount = f"type=bind,source={writable_parent},target={writable_parent}"
            self.assertIn(protected_parser, test_run)
            self.assertGreater(test_run.index(protected_parser), test_run.index(writable_mount))

    def test_pre_adoption_gate_rejects_unavailable_parser_wheel_before_trusted_tests(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-parser-missing-") as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            candidate = root / "candidate"
            trusted_tests = trusted / release.PREFIX / "tests"
            candidate_tests = candidate / release.PREFIX / "tests"
            trusted_tests.mkdir(parents=True)
            candidate_tests.mkdir(parents=True)
            (trusted / release.PREFIX / "release.py").write_text("# trusted fixture\n", encoding="utf-8")
            (trusted_tests / "test_release.py").write_text("# trusted fixture\n", encoding="utf-8")
            (trusted / release.REPOSITORY_CONF).parent.mkdir(parents=True, exist_ok=True)
            (trusted / release.REPOSITORY_CONF).write_text("# trusted fixture\n", encoding="utf-8")
            (candidate / release.PREFIX / "release.py").write_text("# candidate fixture\n", encoding="utf-8")
            (candidate_tests / "test_release.py").write_text("# candidate fixture\n", encoding="utf-8")
            (candidate / release.PREFIX / "requirements-policy.txt").write_text(
                "PyYAML==999999.0.0 --hash=sha256:" + "b" * 64 + "\n", encoding="utf-8",
            )
            (candidate / release.PREFIX / "requirements-policy-bootstrap.txt").write_text(
                "PyYAML==999999.0.0 --hash=sha256:" + "b" * 64 + "\n", encoding="utf-8",
            )
            workflow = candidate / release.PREFIX / "workflows/google-osconfig-agent-inventory.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(policy_signing_workflow_fixture(), encoding="utf-8")
            commands = []

            def pip_fails(command, **kwargs):
                commands.append(command)
                if command and command[0].endswith("/docker") and command[1] == "run":
                    if "download" in command:
                        self.assertIn("--require-hashes", command)
                        self.assertIn("--only-binary=:all:", command)
                        self.assertNotIn("--network=none", command)
                        requirement_path = Path(command[command.index("-r") + 1])
                        self.assertIn("PyYAML==999999.0.0", requirement_path.read_text(encoding="utf-8"))
                        return subprocess.CompletedProcess(
                            command, 1, "", "ERROR: No matching distribution found for PyYAML==999999.0.0",
                        )
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(release, "ROOT", trusted), \
                 patch.object(release, "api", return_value={"sha": "a" * 40}), \
                 patch.object(release.shutil, "which",
                              side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None), \
                 patch.object(release.subprocess, "run", side_effect=pip_fails), \
                 self.assertRaisesRegex(ValueError, "Official PyYAML wheel resolution failed"):
                release.check_policy(candidate)

            container_commands = [command for command in commands
                                  if command and command[0].endswith("/docker") and command[1] == "run"]
            self.assertEqual(len(container_commands), 1)
            self.assertNotIn("-c", container_commands[0], "trusted tests ran after pip rejected the pin")

    def test_pre_adoption_gate_rejects_symlinked_python_inputs(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-symlink-") as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            tests = candidate / release.PREFIX / "tests"
            tests.mkdir(parents=True)
            outside = root / "outside.py"
            outside.write_text("raise SystemExit(0)\n", encoding="utf-8")
            (candidate / release.PREFIX / "release.py").symlink_to(outside)
            (tests / "test_release.py").write_text("# test\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing release policy"):
                release.check_policy(candidate)

    def test_pre_adoption_gate_rejects_symlinked_test_directory(self):
        with tempfile.TemporaryDirectory(prefix="osconfig-policy-testdir-") as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            (candidate / release.PREFIX).mkdir(parents=True)
            outside = root / "outside-tests"
            outside.mkdir()
            (outside / "test_release.py").write_text("# test\n", encoding="utf-8")
            (candidate / release.PREFIX / "release.py").write_text("# release\n", encoding="utf-8")
            (candidate / release.PREFIX / "tests").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "missing release policy"):
                release.check_policy(candidate)


if __name__ == "__main__":
    unittest.main()
