"""Native identity and private-bundle integration boundaries."""
import hashlib
import json
import sys
import tempfile
import types
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release

REVIEW_HISTORY_CUTOFF = "2026-10-19T09:00:00Z"


class NativeAdapterTests(unittest.TestCase):
    repo = "warelik/osconfig"

    def exact_candidate_review_pair(self, *, application_only_delta=False,
                                    source_pair_full_ref=False):
        candidate = {
            "schema": 1, "repository": self.repo,
            "upstream_sha": "a" * 40, "application_sha": "b" * 40,
            "configuration_sha": "c" * 40, "patchset_sha256": "d" * 64,
            "recipe_sha256": "e" * 64, "platform": "fedora-44/x86_64",
        }
        source_config, baseline_config = "2" * 40, "3" * 40
        if application_only_delta:
            candidate["configuration_sha"] = baseline_config
        candidate_id = hashlib.sha256(json.dumps(
            candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        full_sha = "1" * 40
        full_ref_key = (hashlib.sha256((source_config + "\0" + baseline_config).encode("utf-8")).hexdigest()
                        if source_pair_full_ref else candidate_id)
        delta_sha = (candidate["application_sha"] if application_only_delta
                     else candidate["configuration_sha"])
        delta_base_sha = "7" * 40 if application_only_delta else baseline_config
        full_state = {
            "schema": 2, "sourceConfig": source_config, "upstream": candidate["upstream_sha"],
            "tag": "20261015.00", "archiveSha256": "4" * 64, "seed": full_sha,
            "candidate": candidate, "candidateId": candidate_id,
            "applicationSha": candidate["application_sha"], "reviewSourceSha": full_sha,
            "baselineConfig": baseline_config, "deltaSha": delta_sha,
            "deltaPr": 92,
        }
        delta_state = {"candidateId": candidate_id, "candidate": candidate,
                       "sourceConfig": source_config, "baselineConfig": baseline_config}
        full = {
            "number": 91, "state": "open",
            "user": {"login": "warelik", "type": "User"},
            "head": {"ref": f"review/{candidate['upstream_sha']}-{full_ref_key}",
                     "sha": full_sha, "repo": {"full_name": self.repo}},
            "base": {"ref": f"review-base/{candidate['upstream_sha']}",
                     "sha": candidate["upstream_sha"], "repo": {"full_name": self.repo}},
            "body": "<!-- osconfig-candidate:v2 "
                    + json.dumps(full_state, sort_keys=True, separators=(",", ":")) + " -->",
        }
        delta = {
            "number": 92, "state": "open",
            "user": {"login": "warelik", "type": "User"},
            "head": {"ref": f"review/changes-{delta_sha}",
                     "sha": delta_sha,
                     "repo": {"full_name": self.repo}},
            "base": {"ref": f"review-base/{delta_base_sha}",
                     "sha": delta_base_sha, "repo": {"full_name": self.repo}},
            "body": "<!-- osconfig-delta:v2 "
                    + json.dumps(delta_state, sort_keys=True, separators=(",", ":")) + " -->",
        }
        return candidate, candidate_id, full, delta

    def test_close_candidate_closes_only_exact_full_delta_manifest_pair(self):
        _candidate, candidate_id, full, delta = self.exact_candidate_review_pair()
        calls = []
        pulls = {91: full, 92: delta}

        def api(route, method="GET", data=None, **_kwargs):
            calls.append((route, method, data))
            number = int(route.rsplit("/", 1)[-1])
            if method == "GET":
                return pulls[number]
            pulls[number] = {**pulls[number], "state": data["state"]}
            return pulls[number]

        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with (patch.dict("os.environ", {"GITHUB_REPOSITORY": self.repo,
                                         "CANDIDATE_PR": "91", "DELTA_PR": "92"}),
              patch.object(release, "api", side_effect=api),
              patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "cleanup_review_refs") as cleanup):
            release.close_candidate()

        patched_numbers = [int(route.rsplit("/", 1)[-1])
                           for route, method, _data in calls if method == "PATCH"]
        self.assertEqual(patched_numbers, [91, 92])
        cleanup.assert_called_once_with(self.repo, owned_pull_numbers={91, 92})

    def test_close_candidate_rejects_mismatched_pair_before_any_closure(self):
        _candidate, candidate_id, full, delta = self.exact_candidate_review_pair()
        delta["body"] = delta["body"].replace(candidate_id, "9" * 64)
        calls = []

        def api(route, method="GET", **_kwargs):
            calls.append((route, method))
            return {91: full, 92: delta}[int(route.rsplit("/", 1)[-1])]

        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with (patch.dict("os.environ", {"GITHUB_REPOSITORY": self.repo,
                                         "CANDIDATE_PR": "91", "DELTA_PR": "92"}),
              patch.object(release, "api", side_effect=api),
              patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "cleanup_review_refs") as cleanup,
              self.assertRaisesRegex(ValueError, "one exact candidate manifest")):
            release.close_candidate()
        self.assertEqual(calls, [
            (f"repos/{self.repo}/pulls/91", "GET"),
            (f"repos/{self.repo}/pulls/92", "GET"),
        ])
        cleanup.assert_not_called()

    def test_close_candidate_accepts_application_only_delta_against_signed_baseline(self):
        _candidate, candidate_id, full, delta = self.exact_candidate_review_pair(
            application_only_delta=True)
        pulls = {91: full, 92: delta}
        patched = []

        def api(route, method="GET", data=None, **_kwargs):
            number = int(route.rsplit("/", 1)[-1])
            if method == "PATCH":
                patched.append(number)
                pulls[number] = {**pulls[number], "state": data["state"]}
            return pulls[number]

        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with (patch.dict("os.environ", {"GITHUB_REPOSITORY": self.repo,
                                         "CANDIDATE_PR": "91", "DELTA_PR": "92"}),
              patch.object(release, "api", side_effect=api),
              patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "cleanup_review_refs") as cleanup):
            release.close_candidate()
        self.assertEqual(patched, [91, 92])
        cleanup.assert_called_once_with(self.repo, owned_pull_numbers={91, 92})

    def test_close_candidate_accepts_source_and_baseline_hash_full_ref(self):
        _candidate, candidate_id, full, delta = self.exact_candidate_review_pair(
            source_pair_full_ref=True)
        pulls = {91: full, 92: delta}
        patched = []

        def api(route, method="GET", data=None, **_kwargs):
            number = int(route.rsplit("/", 1)[-1])
            if method == "PATCH":
                patched.append(number)
                pulls[number] = {**pulls[number], "state": data["state"]}
            return pulls[number]

        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with (patch.dict("os.environ", {"GITHUB_REPOSITORY": self.repo,
                                         "CANDIDATE_PR": "91", "DELTA_PR": "92"}),
              patch.object(release, "api", side_effect=api),
              patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "cleanup_review_refs") as cleanup):
            release.close_candidate()
        self.assertEqual(patched, [91, 92])
        cleanup.assert_called_once_with(self.repo, owned_pull_numbers={91, 92})

    def test_close_candidate_rejects_unrelated_full_ref_before_any_closure(self):
        _candidate, candidate_id, full, delta = self.exact_candidate_review_pair()
        full["head"]["ref"] = "review/" + "a" * 40 + "-" + "9" * 64
        calls = []

        def api(route, method="GET", **_kwargs):
            calls.append((route, method))
            return {91: full, 92: delta}[int(route.rsplit("/", 1)[-1])]

        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with (patch.dict("os.environ", {"GITHUB_REPOSITORY": self.repo,
                                         "CANDIDATE_PR": "91", "DELTA_PR": "92"}),
              patch.object(release, "api", side_effect=api),
              patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "cleanup_review_refs") as cleanup,
              self.assertRaisesRegex(ValueError, "one exact candidate manifest")):
            release.close_candidate()
        self.assertEqual(calls, [
            (f"repos/{self.repo}/pulls/91", "GET"),
            (f"repos/{self.repo}/pulls/92", "GET"),
        ])
        cleanup.assert_not_called()

    def test_policy_pair_cleanup_accepts_v1_full_marker_and_exact_manifest_context(self):
        candidate, candidate_id, full, delta = self.exact_candidate_review_pair()
        policy_marker = {
            "schema": 1, "proposalPr": 12, "proposalHead": "4" * 40,
            "candidate": candidate, "candidateId": candidate_id,
            "applicationSha": candidate["application_sha"],
            "reviewSourceSha": full["head"]["sha"],
            "baselineConfig": "3" * 40, "deltaSha": delta["head"]["sha"],
            "deltaPr": delta["number"],
        }
        full["body"] = "<!-- osconfig-policy-candidate:v1 " + json.dumps(
            policy_marker, sort_keys=True, separators=(",", ":")) + " -->"
        contexts = {
            "full": {"pr": 91, "review_sha": full["head"]["sha"],
                     "base_sha": full["base"]["sha"], "head_branch": full["head"]["ref"],
                     "base_branch": full["base"]["ref"]},
            "delta": {"pr": 92, "review_sha": delta["head"]["sha"],
                      "base_sha": delta["base"]["sha"], "head_branch": delta["head"]["ref"],
                      "base_branch": delta["base"]["ref"]},
        }
        pulls = {91: full, 92: delta}
        patched = []

        def api(route, method="GET", data=None, **_kwargs):
            number = int(route.rsplit("/", 1)[-1])
            if method == "PATCH":
                patched.append(number)
                pulls[number] = {**pulls[number], "state": data["state"]}
            return pulls[number]

        with (patch.dict("os.environ", {"GITHUB_REPOSITORY": self.repo,
                                         "CANDIDATE_PR": "91", "DELTA_PR": "92"}),
              patch.object(release, "api", side_effect=api),
              patch.object(release, "cleanup_review_refs") as cleanup):
            release.close_review_context_pair(self.repo, contexts)
        self.assertEqual(patched, [91, 92])
        cleanup.assert_called_once_with(self.repo, owned_pull_numbers={91, 92})

    def test_policy_pair_cleanup_rejects_changed_context_before_any_closure(self):
        _candidate, _candidate_id, full, delta = self.exact_candidate_review_pair()
        contexts = {
            "full": {"pr": 91, "review_sha": full["head"]["sha"],
                     "base_sha": full["base"]["sha"], "head_branch": full["head"]["ref"],
                     "base_branch": full["base"]["ref"]},
            "delta": {"pr": 92, "review_sha": delta["head"]["sha"],
                      "base_sha": delta["base"]["sha"], "head_branch": "review/other-delta",
                      "base_branch": delta["base"]["ref"]},
        }
        calls = []

        def api(route, method="GET", **_kwargs):
            calls.append((route, method))
            return {91: full, 92: delta}[int(route.rsplit("/", 1)[-1])]

        with (patch.dict("os.environ", {"GITHUB_REPOSITORY": self.repo,
                                         "CANDIDATE_PR": "91", "DELTA_PR": "92"}),
              patch.object(release, "api", side_effect=api),
              patch.object(release, "cleanup_review_refs") as cleanup,
              self.assertRaisesRegex(ValueError, "Exact delta review PR changed")):
            release.close_review_context_pair(self.repo, contexts)
        self.assertEqual(calls, [
            (f"repos/{self.repo}/pulls/91", "GET"),
            (f"repos/{self.repo}/pulls/92", "GET"),
        ])
        cleanup.assert_not_called()

    def test_delta_review_branch_uses_the_reserved_changes_namespace(self):
        source_sha = "a" * 40
        self.assertEqual(release.delta_review_branch(source_sha),
                         f"review/changes-{source_sha}")
        with self.assertRaisesRegex(ValueError, "exact source SHA"):
            release.delta_review_branch("abbreviated")

    def test_closed_candidate_recovers_from_exact_pr_archive_after_branch_cleanup(self):
        head_sha = "a" * 40
        app_sha, source_config = "c" * 40, "b" * 40
        identity = {
            "schema": 2, "upstream": "d" * 40, "sourceConfig": source_config,
            "archiveSha256": "e" * 64, "seed": "f" * 40,
            "candidate": {"application_sha": app_sha}, "reviewSourceSha": head_sha,
        }
        pull = {"number": 77, "state": "closed",
                "head": {"sha": head_sha, "repo": {"full_name": self.repo}},
                "body": "<!-- osconfig-candidate:v2 "
                        + json.dumps(identity, sort_keys=True, separators=(",", ":"))
                        + " -->"}
        archive = {"ref": "refs/pull/77/head",
                   "object": {"type": "commit", "sha": head_sha}}
        recovered = release.existing_candidate_state(
            pull, upstream=identity["upstream"], config=source_config,
            archive_sha=identity["archiveSha256"])
        self.assertEqual(recovered["sourceConfig"], source_config)
        self.assertEqual(recovered["candidate"]["application_sha"], app_sha)
        self.assertEqual(recovered["reviewSourceSha"], head_sha)
        with patch.object(release, "api", return_value=archive) as native, \
                patch.object(release, "run", side_effect=[None, head_sha]) as git:
            fetched = release.fetch_archived_review_pr_head(Path("/candidate/git"), self.repo, pull)
        self.assertEqual(fetched, head_sha)
        native.assert_called_once_with(f"repos/{self.repo}/git/ref/pull/77/head")
        self.assertEqual(git.call_args_list[0].args,
                         ("git", "fetch", "--no-tags", "origin", "refs/pull/77/head"))
        self.assertNotIn("refs/heads/", git.call_args_list[0].args[-1])
        with patch.object(release, "api", return_value={
                "ref": "refs/pull/77/head", "object": {"type": "commit", "sha": "b" * 40}}), \
                self.assertRaisesRegex(ValueError, "differs from the exact review PR head"):
            release.fetch_archived_review_pr_head(Path("/candidate/git"), self.repo, pull)

    def test_native_review_history_overrides_legacy_snapshot_for_same_finding_id(self):
        finding_id = "review:91:604"
        snapshot = {"finding_id": finding_id, "candidate_id": "a" * 64,
                    "scope": "full", "source": "review", "source_sha": "b" * 40,
                    "native_id": 604, "body": "old snapshot body", "path": None,
                    "line": None, "severity": "unlabelled"}
        native = {**snapshot, "candidate_id": "c" * 64, "source_sha": "d" * 40,
                  "body": "native normalized body", "source_tree_sha": "e" * 40}
        unrelated = {**snapshot, "finding_id": "inline:90:602"}

        merged = release._native_authoritative_findings([snapshot, unrelated], [native])

        self.assertEqual(merged, [unrelated, native])
        self.assertEqual(merged[-1]["body"], "native normalized body")
        self.assertEqual(merged[-1]["source_sha"], "d" * 40)
        self.assertEqual(merged[-1]["source_tree_sha"], "e" * 40)

    def test_latest_exact_owner_review_request_wins_and_must_be_immutable(self):
        marker = release.owner_review_marker("c" * 64, "full", "a" * 40, "b" * 40)
        earlier = {"id": 900, "user": {"login": "warelik", "type": "User"},
                   "body": marker, "created_at": "2026-10-19T10:00:00Z",
                   "updated_at": "2026-10-19T10:00:00Z"}
        later = {**earlier, "id": 701, "created_at": "2026-10-19T10:01:00Z",
                  "updated_at": "2026-10-19T10:01:00Z"}
        latest = {**later, "id": 702}
        bot = {**latest, "id": 703, "user": {"login": "github-actions[bot]", "type": "Bot"},
               "created_at": "2026-10-19T10:02:00Z",
               "updated_at": "2026-10-19T10:02:00Z"}
        self.assertIs(release.latest_owner_review_request(
            [earlier, later, latest, bot], marker, "warelik"), latest)
        edited = {**latest, "updated_at": "2026-10-19T10:03:00Z"}
        with self.assertRaisesRegex(ValueError, "Latest native owner review request was edited"):
            release.latest_owner_review_request([earlier, edited], marker, "warelik")

    def test_mismatched_native_workflow_sha_requires_contents_and_graphql_proof(self):
        run_record = {
            "id": 801, "run_attempt": 2, "path": release.WORKFLOW_PATH,
            "head_sha": "a" * 40, "node_id": "WFR_kgDOExample",
            "event": "pull_request_target", "head_branch": "repair/verified",
        }
        run_file = {"type": "file", "sha": "c" * 40}
        reserved_file = {"type": "file", "sha": "c" * 40}
        graphql = {"data": {"node": {"id": run_record["node_id"]}}}
        routes = {
            f"repos/{self.repo}/actions/runs/801/attempts/2": run_record,
            f"repos/{self.repo}/contents/{release.WORKFLOW_PATH}?ref={'a' * 40}": run_file,
            f"repos/{self.repo}/contents/{release.WORKFLOW_PATH}?ref={'b' * 40}": reserved_file,
            "graphql": graphql,
        }
        core = types.SimpleNamespace(validate_workflow_source=Mock(return_value=True))
        calls = []

        def api(route, **kwargs):
            calls.append((route, kwargs))
            return routes[route]

        with patch.object(release, "api", side_effect=api):
            proof = release.native_workflow_source_proof(
                self.repo, run_record, "b" * 40, release.WORKFLOW_PATH)
            result = release.validate_native_workflow_source(
                self.repo, run_record, "b" * 40, release.WORKFLOW_PATH, core=core)

        self.assertEqual(proof, {"run_file": run_file, "reserved_file": reserved_file,
                                 "workflow_run": graphql})
        self.assertIs(result, run_record)
        checked_proof = core.validate_workflow_source.call_args.args[-1]
        self.assertEqual(checked_proof, proof)
        self.assertEqual(calls[-1][0], "graphql")

    def test_current_workflow_guard_validates_the_exact_native_attempt(self):
        run_record = {
            "id": 801, "run_attempt": 2, "path": release.WORKFLOW_PATH,
            "head_sha": "a" * 40, "node_id": "WFR_kgDOExample",
            "event": "pull_request_target", "head_branch": "repair/verified",
        }
        run_file = {"type": "file", "sha": "c" * 40}
        reserved_file = {"type": "file", "sha": "c" * 40}
        graphql = {"data": {"node": {"id": run_record["node_id"]}}}
        routes = {
            f"repos/{self.repo}/actions/runs/801/attempts/2": run_record,
            f"repos/{self.repo}/contents/{release.WORKFLOW_PATH}?ref={'a' * 40}": run_file,
            f"repos/{self.repo}/contents/{release.WORKFLOW_PATH}?ref={'b' * 40}": reserved_file,
            "graphql": graphql,
        }
        core = types.SimpleNamespace(validate_workflow_source=Mock(return_value=True))
        with patch.object(release, "api", side_effect=lambda route, **_kwargs: routes[route]), \
                patch.object(release, "lifecycle_module", return_value=core):
            checked = release.validate_current_workflow_source(
                self.repo, 801, 2, "b" * 40, core=core)
        self.assertIs(checked, run_record)
        self.assertEqual(core.validate_workflow_source.call_args.args,
                         (self.repo, run_record, "b" * 40, release.WORKFLOW_PATH,
                          {"run_file": run_file, "reserved_file": reserved_file,
                           "workflow_run": graphql}))

    def test_native_final_history_retains_mismatched_workflow_source_proof(self):
        candidate = {"repository": self.repo, "upstream_sha": "1" * 40,
                     "application_sha": "2" * 40, "configuration_sha": "3" * 40}
        candidate_id, workflow_sha = "c" * 64, "b" * 40
        final = {"schema": 1, "candidate_id": candidate_id, "run_id": 800,
                 "run_attempt": 1, "workflow_sha": workflow_sha}
        body = (
            "<!-- fork-candidate:v1 "
            + json.dumps(candidate, sort_keys=True, separators=(",", ":"))
            + " -->\n<!-- fork-final:v1 "
            + json.dumps(final, sort_keys=True, separators=(",", ":")) + " -->"
        )
        reservation = {"id": 91, "issue_url": f"https://api.github.com/repos/{self.repo}/issues/91",
                       "user": {"login": "github-actions[bot]", "type": "Bot"},
                       "body": body, "created_at": "2026-10-19T10:02:00Z",
                       "updated_at": "2026-10-19T10:02:00Z"}
        run_record = {
            "id": 800, "run_attempt": 1, "path": release.WORKFLOW_PATH,
            "head_sha": "a" * 40, "node_id": "WFR_example",
            "event": "pull_request_target", "head_branch": "repair/verified",
            "status": "completed", "conclusion": "failure",
            "created_at": "2026-10-19T10:01:00Z", "updated_at": "2026-10-19T10:05:00Z",
        }
        workflow_run = {"id": 800, "run_attempt": 1,
                        "updated_at": "2026-10-19T10:05:00Z"}
        skipped_jobs = [
            {"id": 1, "name": name, "status": "completed", "conclusion": "skipped",
             "steps": []}
            for name in release.FINAL_REQUIRED_JOBS
        ]
        proof = {"run_file": {"sha": "d" * 40},
                 "reserved_file": {"sha": "d" * 40},
                 "workflow_run": {"data": {"node": {"id": "WFR_example"}}}}

        def pages(route):
            if route == f"repos/{self.repo}/issues/comments":
                return [reservation]
            if route.endswith("/attempts/1/jobs"):
                return skipped_jobs
            return []

        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with patch.dict("os.environ", {"CANDIDATE_PR": "91"}), \
                patch.object(release, "lifecycle_module", return_value=core), \
                patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "native_workflow_runs", return_value=[workflow_run]), \
                patch.object(release, "api", return_value=run_record), \
                patch.object(release, "native_workflow_source_proof", return_value=proof) as proof_reader:
            history = release.native_final_history(
                self.repo, candidate, {"published_at": "2026-10-19T10:00:00Z"}, 999, 1)

        self.assertTrue(history["complete"])
        self.assertEqual(history["attempts"][0]["workflow_source"], proof)
        self.assertEqual(history["attempts"][0]["run"]["node_id"], run_record["node_id"])
        proof_reader.assert_called_once_with(
            self.repo, run_record, workflow_sha, release.WORKFLOW_PATH,
            cache={})

    def test_dismissed_native_review_passes_raw_issue_events_to_shared_core(self):
        candidate = {"repository": self.repo, "application_sha": "a" * 40,
                     "configuration_sha": "b" * 40}
        review_sha, base_sha = candidate["configuration_sha"], "d" * 40
        context = {"pr": 92, "review_sha": review_sha, "base_sha": base_sha,
                   "head_branch": release.delta_review_branch(review_sha),
                   "base_branch": "review-base/base"}
        request = {"id": 92, "user": {"login": "warelik", "type": "User"},
                   "body": "exact request", "created_at": "2026-10-19T10:00:00Z",
                   "updated_at": "2026-10-19T10:00:00Z"}
        formal = {"id": 501, "state": "DISMISSED", "commit_id": review_sha,
                  "submitted_at": "2026-10-19T10:01:00Z"}
        dismissal = {"id": 601, "event": "review_dismissed",
                     "created_at": "2026-10-19T10:03:00Z",
                     "dismissed_review": {"review_id": "501"},
                     "url": f"https://api.github.com/repos/{self.repo}/issues/events/601"}
        pages_by_route = {
            f"repos/{self.repo}/issues/92/comments": [request],
            f"repos/{self.repo}/pulls/92/reviews": [formal],
            f"repos/{self.repo}/pulls/92/comments": [],
            f"repos/{self.repo}/issues/92/events": [dismissal],
        }
        core = types.SimpleNamespace(
            candidate_identity=Mock(return_value="e" * 64),
            evaluate_review=Mock(return_value={"state": "complete"}),
        )
        with patch.object(release, "lifecycle_module", return_value=core), \
                patch.object(release, "api", return_value={"number": 92}), \
                patch.object(release, "pages", side_effect=lambda route: pages_by_route[route]) as page, \
                patch.object(release, "review_pull_identity", return_value=True), \
                patch.object(release, "latest_owner_review_request", return_value=request), \
                patch.object(release, "native_source_git_data", return_value={"application": {}}), \
                patch.object(release, "_resolved_review_commits", return_value={}):
            result = release.evaluate_native_review_scope(
                self.repo, context, candidate, "delta", accepted_baseline={})

        self.assertEqual(result, {"state": "complete"})
        target = core.evaluate_review.call_args.args[0]
        self.assertEqual(target["review_dismissals"], [dismissal])
        self.assertIn(f"repos/{self.repo}/issues/92/events", [
            call.args[0] for call in page.call_args_list])

    def test_zero_exit_requires_the_exact_completed_nonempty_suite_protocol(self):
        valid = b"OSCONFIG_POLICY_COMPLETE:101:pass\n"
        self.assertTrue(release.policy_completion_succeeded(0, valid))
        for status, output in ((0, b""), (1, valid), (0, b"OSCONFIG_POLICY_COMPLETE:0:pass\n"),
                               (0, b"PRIVATE SOURCE\n" + valid), (0, valid + valid)):
            with self.subTest(status=status, output=output):
                self.assertFalse(release.policy_completion_succeeded(status, output))

    def test_shared_signer_contract_cannot_fall_back_to_the_legacy_workflow(self):
        from test_policy_isolation import policy_signing_workflow_fixture
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.yml"
            path.write_text(policy_signing_workflow_fixture(), encoding="utf-8")
            release.validate_signing_workflow(path)
            with self.assertRaises(ValueError):
                release.validate_signing_workflow(path, shared=True)

    def test_required_job_with_executed_steps_and_no_timestamp_is_not_unspent(self):
        for helper in (release.native_heavy_job_started, release.native_policy_job_started):
            self.assertFalse(helper({"started_at": "2026-10-19T10:00:00Z",
                                     "conclusion": "skipped", "steps": []}))
            with self.assertRaisesRegex(ValueError, "start timestamp"):
                helper({"started_at": None, "conclusion": "success",
                        "steps": [{"status": "completed", "conclusion": "success"}]})
            with self.assertRaisesRegex(ValueError, "start timestamp"):
                helper({"started_at": None, "status": "completed", "conclusion": "success",
                        "steps": []})

    def test_native_review_history_includes_unmarked_formal_and_inline_records(self):
        source = {"repository": self.repo}
        published_at = "2026-10-19T09:00:00Z"
        pull = {"number": 91, "updated_at": "2026-10-19T10:00:00Z",
                "state": "open", "head": {"sha": "a" * 40,
                    "ref": "review/source", "repo": {"full_name": self.repo}},
                "base": {"sha": "b" * 40, "ref": "review-base/source"}}
        formal, inline = [{"id": 92}], [{"id": 93}]
        proof = {"variable": {"value": json.dumps({"publication": {"published_at": published_at}})}}
        core = types.SimpleNamespace(review_history=Mock(return_value={"findings": [], "dispositions": []}))
        def pages(route):
            if "/pulls?" in route:
                return [pull]
            if route.endswith("/reviews"):
                return formal
            if route.endswith("/pulls/91/comments"):
                return inline
            return []
        with patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "api", return_value=pull), \
                patch.object(release, "_resolved_review_commits", return_value={}), \
                patch.object(release, "lifecycle_module", return_value=core):
            release.native_review_finding_history(self.repo, source, proof)
        args = core.review_history.call_args.args
        kwargs = core.review_history.call_args.kwargs
        self.assertEqual(args[0], source)
        self.assertEqual(args[1][0]["reviews"], formal)
        self.assertEqual(args[1][0]["inline"], inline)
        self.assertEqual(args[2], published_at)
        self.assertEqual(kwargs.keys(), {"read_native"})
        native_commit = {"sha": "c" * 40}
        route = f"repos/{self.repo}/git/commits/{native_commit['sha']}"
        with patch.object(release, "api", return_value=native_commit) as native_get:
            self.assertIs(kwargs["read_native"](route), native_commit)
        native_get.assert_called_once_with(route)

    def test_owner_disposition_preserves_its_native_comment_identity(self):
        disposition = {"schema": 1, "candidate_id": "c" * 64,
                       "source_sha": "d" * 40,
                       "findings": [{"finding_id": "finding-1", "status": "disproved",
                                     "evidence": "Exact reviewed source disproves this finding."}]}
        comment = {"id": 94, "created_at": "2026-10-19T10:00:00Z",
                   "updated_at": "2026-10-19T10:00:00Z",
                   "user": {"login": "warelik", "type": "User"},
                   "body": "<!-- fork-review-disposition:v1 " +
                           json.dumps(disposition, sort_keys=True, separators=(",", ":")) + " -->"}
        with patch.object(release, "pages", return_value=[comment]):
            _, _, _, values = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
        self.assertEqual(values["finding-1"]["native_comment"], {
            "id": 94, "created_at": comment["created_at"],
            "updated_at": comment["updated_at"], "user": comment["user"],
        })

    def test_finding_batch_requires_immutable_native_owner_comment_and_preserves_all_findings(self):
        candidate_id = "c" * 64
        candidate = {"repository": self.repo}
        contexts = {"full": {"pr": 91}, "delta": {"pr": 92}}
        findings = [
            {"finding_id": "review:91:603", "candidate_id": candidate_id,
             "scope": "full", "source_sha": "d" * 40, "native_id": 603,
             "body": "P1: first preserved finding"},
            {"finding_id": "inline:91:604", "candidate_id": candidate_id,
             "scope": "full", "source_sha": "d" * 40, "native_id": 604,
             "body": "Second preserved finding"},
        ]
        marker = "<!-- fork-finding-batch:v1 " + json.dumps({
            "schema": 1, "candidate_id": candidate_id, "candidate": candidate,
            "review_contexts": contexts, "findings": findings,
        }, sort_keys=True, separators=(",", ":")) + " -->"
        valid = {"id": 95, "created_at": "2026-10-19T10:00:00Z",
                 "updated_at": "2026-10-19T10:00:00Z",
                 "user": {"login": "warelik", "type": "User"}, "body": marker}
        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))

        with (patch.object(release, "pages", return_value=[valid]),
              patch.object(release, "lifecycle_module", return_value=core)):
            comments, loaded, sources, dispositions = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

        self.assertEqual(comments, [valid])
        self.assertEqual(loaded, findings)
        self.assertEqual(sources, {candidate_id: {
            "candidate": candidate, "review_contexts": contexts,
        }})
        self.assertEqual(dispositions, {})

        bot_copy = {**valid, "id": 96,
                    "user": {"login": "github-actions[bot]", "type": "Bot"}}
        with patch.object(release, "pages", return_value=[bot_copy]):
            self.assertEqual(release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)[1:4],
                             ([], {}, {}))

        invalid = []
        for native_id in (0, -1, True, False, None, "95"):
            comment = dict(valid)
            comment["id"] = native_id
            invalid.append((comment, "positive native comment ID"))
        missing_id = dict(valid)
        missing_id.pop("id")
        invalid.append((missing_id, "positive native comment ID"))
        for field in ("created_at", "updated_at"):
            comment = dict(valid)
            comment.pop(field)
            invalid.append((comment, "timestamps are missing"))
        for field, value, message in (("created_at", "not-a-time", "timestamps"),
                                      ("updated_at", "2026-10-19T10:01:00Z", "edited"),
                                      ("created_at", "2026-10-19T10:00:00", "timestamps")):
            comment = dict(valid)
            comment[field] = value
            invalid.append((comment, message))

        for comment, message in invalid:
            with self.subTest(comment_id=comment.get("id"),
                              created_at=comment.get("created_at"),
                              updated_at=comment.get("updated_at")):
                with (patch.object(release, "pages", return_value=[comment]),
                      patch.object(release, "lifecycle_module", return_value=core),
                      self.assertRaisesRegex(ValueError, message)):
                    release.load_review_finding_history(
                        self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

    def test_finding_batches_order_source_by_timestamp_then_id_and_union_all_history(self):
        candidate_ids = {"same": "a" * 64, "other": "b" * 64}
        candidates = {
            "same": {"repository": self.repo, "label": "same"},
            "other": {"repository": self.repo, "label": "other"},
        }
        contexts = {
            "old": {"full": {"pr": 90}, "delta": {"pr": 91}},
            "middle": {"full": {"pr": 92}, "delta": {"pr": 93}},
            "latest": {"full": {"pr": 94}, "delta": {"pr": 95}},
            "other": {"full": {"pr": 96}, "delta": {"pr": 97}},
        }

        def finding(finding_id, candidate_id, native_id):
            return {"finding_id": finding_id, "candidate_id": candidate_id,
                    "scope": "full", "source_sha": "d" * 40,
                    "native_id": native_id, "body": finding_id}

        records = []
        for comment_id, created_at, label, context_key, finding_id, native_id in (
                (99, "2026-10-19T10:00:00Z", "same", "old", "review:90:1", 1),
                (10, "2026-10-19T10:01:00Z", "same", "middle", "review:90:2", 2),
                (11, "2026-10-19T10:01:00Z", "same", "latest", "inline:90:3", 3),
                (12, "2026-10-19T10:01:00Z", "other", "other", "review:96:4", 4)):
            candidate_id = candidate_ids[label]
            value = {"schema": 1, "candidate_id": candidate_id,
                     "candidate": candidates[label],
                     "review_contexts": contexts[context_key],
                     "findings": [finding(finding_id, candidate_id, native_id)]}
            body = "<!-- fork-finding-batch:v1 " + json.dumps(
                value, sort_keys=True, separators=(",", ":")) + " -->"
            records.append({
                "id": comment_id, "created_at": created_at, "updated_at": created_at,
                "user": {"login": "warelik", "type": "User"}, "body": body,
            })
        core = types.SimpleNamespace(candidate_identity=Mock(
            side_effect=lambda candidate: candidate_ids[candidate["label"]]))
        expected_findings = ["inline:90:3", "review:90:1", "review:90:2", "review:96:4"]
        for order in (records, [records[2], records[0], records[3], records[1]]):
            with self.subTest(order=[comment["id"] for comment in order]), \
                    patch.object(release, "pages", return_value=order), \
                    patch.object(release, "lifecycle_module", return_value=core):
                _comments, loaded, sources, _dispositions = release.load_review_finding_history(
                    self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
            self.assertEqual([item["finding_id"] for item in loaded], expected_findings)
            self.assertEqual(sources[candidate_ids["same"]], {
                "candidate": candidates["same"], "review_contexts": contexts["latest"],
            })
            self.assertEqual(sources[candidate_ids["other"]], {
                "candidate": candidates["other"], "review_contexts": contexts["other"],
            })

    def test_finding_batch_envelope_and_json_schema_are_strict(self):
        candidate_id = "c" * 64
        candidate = {"repository": self.repo}
        value = {"schema": 1, "candidate_id": candidate_id, "candidate": candidate,
                 "review_contexts": {"full": {"pr": 91}, "delta": {"pr": 92}},
                 "findings": []}
        prefix = "<!-- fork-finding-batch:v1"
        suffix = " -->"

        def comment(body):
            return {"id": 95, "created_at": "2026-10-19T10:00:00Z",
                    "updated_at": "2026-10-19T10:00:00Z",
                    "user": {"login": "warelik", "type": "User"}, "body": body}

        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        invalid_bodies = [
            (prefix + " {truncated", "envelope is malformed"),
            (prefix + " {\"schema\":1} -->\n" + prefix + " {truncated",
             "envelope is malformed"),
            (prefix + " {\"schema\":1} -->\n" + prefix + " {\"schema\":1} -->",
             "marker is ambiguous"),
        ]
        for body, message in invalid_bodies:
            with self.subTest(body=body), \
                    patch.object(release, "pages", return_value=[comment(body)]), \
                    patch.object(release, "lifecycle_module", return_value=core), \
                    self.assertRaisesRegex(ValueError, message):
                release.load_review_finding_history(
                    self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

        for schema in (False, True, 1.0, 2):
            with self.subTest(schema=schema):
                malformed = {**value, "schema": schema}
                body = prefix + " " + json.dumps(malformed, sort_keys=True) + suffix
                with (patch.object(release, "pages", return_value=[comment(body)]),
                      patch.object(release, "lifecycle_module", return_value=core),
                      self.assertRaisesRegex(ValueError, "exact candidate")):
                    release.load_review_finding_history(
                        self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

        extra = {**value, "unexpected": True}
        body = prefix + " " + json.dumps(extra, sort_keys=True) + suffix
        with (patch.object(release, "pages", return_value=[comment(body)]),
              patch.object(release, "lifecycle_module", return_value=core),
              self.assertRaisesRegex(ValueError, "exact candidate")):
            release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

        duplicate_json = (
            '{"schema":1,"schema":1,"candidate_id":"' + candidate_id
            + '","candidate":{"repository":"' + self.repo
            + '"},"review_contexts":{"full":{"pr":91},"delta":{"pr":92}},"findings":[]}')
        body = prefix + " " + duplicate_json + suffix
        with (patch.object(release, "pages", return_value=[comment(body)]),
              patch.object(release, "lifecycle_module", return_value=core),
              self.assertRaisesRegex(ValueError, "malformed")):
            release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

    def test_finding_batch_writer_roundtrips_nested_marker_text_without_envelope_collision(self):
        candidate_id = "c" * 64
        candidate = {"repository": self.repo}
        finding = {"finding_id": "review:91:603", "candidate_id": candidate_id,
                   "scope": "full", "source_sha": "d" * 40, "native_id": 603,
                   "body": 'Quoted <!-- fork-finding-batch:v1 {"schema":1} --> and --> text.'}
        pair = {"complete": True, "observed_findings": [finding]}
        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        posted = []
        with (patch.object(release, "pages", return_value=[]),
              patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "api", side_effect=lambda _path, **kwargs:
                             posted.append(kwargs["data"]["body"]))):
            release.record_review_finding_batch(
                self.repo, 91, candidate,
                {"full": {"pr": 91}, "delta": {"pr": 92}}, pair, "owner-token")
        self.assertEqual(len(posted), 1)
        self.assertNotIn('<!-- fork-finding-batch:v1 {"schema":1} -->', posted[0])
        self.assertIn("\\u003c!-- fork-finding-batch:v1", posted[0])
        native_comment = {
            "id": 96, "created_at": "2026-10-19T10:00:00Z",
            "updated_at": "2026-10-19T10:00:00Z",
            "user": {"login": "warelik", "type": "User"}, "body": posted[0],
        }
        with (patch.object(release, "pages", return_value=[native_comment]),
              patch.object(release, "lifecycle_module", return_value=core)):
            _comments, loaded, _sources, _dispositions = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
        self.assertEqual(loaded, [finding])

    def test_finding_batch_reader_accepts_legacy_unescaped_nested_marker_text(self):
        candidate_id = "c" * 64
        candidate = {"repository": self.repo}
        finding = {"finding_id": "review:91:603", "candidate_id": candidate_id,
                   "scope": "full", "source_sha": "d" * 40, "native_id": 603,
                   "body": 'Legacy text <!-- fork-finding-batch:v1 {"schema":1} --> and --> text.'}
        value = {"schema": 1, "candidate_id": candidate_id, "candidate": candidate,
                 "review_contexts": {"full": {"pr": 91}, "delta": {"pr": 92}},
                 "findings": [finding]}
        body = "<!-- fork-finding-batch:v1 " + json.dumps(
            value, sort_keys=True, separators=(",", ":")) + " -->"
        comment = {"id": 97, "created_at": "2026-10-19T10:00:00Z",
                   "updated_at": "2026-10-19T10:00:00Z",
                   "user": {"login": "warelik", "type": "User"}, "body": body}
        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with (patch.object(release, "pages", return_value=[comment]),
              patch.object(release, "lifecycle_module", return_value=core)):
            _comments, loaded, _sources, _dispositions = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
        self.assertEqual(loaded, [finding])

    def test_legacy_batch_payload_isolated_from_owner_protocol_scanners(self):
        candidate_id = "c" * 64
        candidate = {"repository": self.repo, "upstream_sha": "1" * 40,
                     "application_sha": "2" * 40, "configuration_sha": "3" * 40}
        contexts = {"full": {"pr": 91}, "delta": {"pr": 92}}
        nested_markers = (
            '<!-- osconfig-codex:' + "d" * 40 + " -->\n"
            '<!-- fork-review-disposition:v1 {"nested":true} -->\n'
            '<!-- fork-final-retry:v1 {"nested":true} -->\n'
            '<!-- fork-final:v1 {"nested":true} -->\n'
            '<!-- fork-candidate:v1 {"nested":true} -->\n'
            '<!-- fork-policy-pair:v1 {"nested":true} -->'
        )
        finding = {"finding_id": "review:91:603", "candidate_id": candidate_id,
                   "scope": "full", "source_sha": candidate["application_sha"],
                   "native_id": 603, "body": "Legacy quoted payload: " + nested_markers}
        snapshot = {"schema": 1, "candidate_id": candidate_id, "candidate": candidate,
                    "review_contexts": contexts, "findings": [finding]}
        batch = "<!-- fork-finding-batch:v1 " + json.dumps(
            snapshot, sort_keys=True, separators=(",", ":")) + " -->"
        disposition = {"schema": 1, "candidate_id": candidate_id,
                       "source_sha": candidate["application_sha"],
                       "findings": [{"finding_id": "carried:91:1", "status": "disproved",
                                     "evidence": "The exact reviewed source disproves this finding."}]}
        disposition_marker = "<!-- fork-review-disposition:v1 " + json.dumps(
            disposition, sort_keys=True, separators=(",", ":")) + " -->"
        policy_pair = {
            "schema": 1, "candidate": candidate, "candidateIdentity": candidate_id,
            "acceptedBaselineProof": {}, "findingHistory": [], "findingDispositions": [],
            "reviewContexts": contexts, "configSha": "a" * 40,
            "proposalPr": 90, "proposalHeadSha": "b" * 40,
            "candidatePr": 91, "deltaPr": 92,
        }
        policy_pair_marker = "<!-- fork-policy-pair:v1 " + json.dumps(
            policy_pair, sort_keys=True, separators=(",", ":")) + " -->"
        real_review = f"<!-- osconfig-codex:{'e' * 40} -->"
        real_retry = "<!-- fork-final-retry:v1 " + json.dumps({
            "schema": 1, "candidate_id": candidate_id,
            "previous_run_id": 700, "previous_run_attempt": 1,
        }, sort_keys=True, separators=(",", ":")) + " -->"
        owner_comment = {
            "id": 106, "created_at": "2026-10-19T10:00:00Z",
            "updated_at": "2026-10-19T10:00:00Z",
            "issue_url": f"https://api.github.com/repos/{self.repo}/issues/91",
            "user": {"login": "warelik", "type": "User"},
            "body": (batch + "\n" + disposition_marker + "\n" + policy_pair_marker
                     + "\n" + real_review + "\n" + real_retry),
        }
        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))

        protocol_body = release._owner_protocol_comment_body(
            "warelik", owner_comment, cutoff=release.parse_utc(REVIEW_HISTORY_CUTOFF))
        self.assertNotIn("fork-final:v1", protocol_body)
        self.assertNotIn("fork-candidate:v1", protocol_body)
        self.assertNotIn("fork-policy-pair:v1", protocol_body)
        self.assertIn(disposition_marker, protocol_body)
        self.assertIn(policy_pair_marker, protocol_body)
        self.assertEqual(release._marker_value(
            release.POLICY_PAIR_MARKER, protocol_body, "paired policy review context"),
            policy_pair)
        self.assertIn(real_retry, protocol_body)
        self.assertIn(real_review, protocol_body)

        now = release.parse_utc(owner_comment["created_at"]) + timedelta(
            seconds=release.REPAIR_WINDOW_SECONDS)
        nested_only = {**owner_comment, "body": batch}
        self.assertFalse(release.review_followup_due(
            [nested_only], sha="d" * 40, now=now))
        self.assertTrue(release.review_followup_due(
            [owner_comment], sha="e" * 40, now=now))

        with (patch.object(release, "pages", return_value=[owner_comment]),
              patch.object(release, "lifecycle_module", return_value=core)):
            _comments, loaded, _sources, prior = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
        self.assertEqual(loaded, [finding])
        self.assertEqual(prior["carried:91:1"]["status"], "disproved")

        with (patch.dict("os.environ", {"CANDIDATE_PR": "91"}),
              patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "pages", return_value=[owner_comment]),
              patch.object(release, "native_workflow_runs", return_value=[])):
            history = release.native_final_history(
                self.repo, candidate, {"published_at": REVIEW_HISTORY_CUTOFF}, 999, 1)
        self.assertTrue(history["complete"])
        self.assertEqual([grant["id"] for grant in history["grants"]], [106])
        self.assertEqual(history["attempts"], [])

        bot_candidate = "<!-- fork-candidate:v1 " + json.dumps(
            candidate, sort_keys=True, separators=(",", ":")) + " -->"
        final = {"schema": 1, "candidate_id": candidate_id, "run_id": 800,
                 "run_attempt": 1, "workflow_sha": "f" * 40}
        bot_final = "<!-- fork-final:v1 " + json.dumps(
            final, sort_keys=True, separators=(",", ":")) + " -->"
        bot_comment = {**owner_comment, "id": 107,
                       "user": {"login": "github-actions[bot]", "type": "Bot"},
                       "body": bot_candidate + "\n" + bot_final}
        with (patch.object(release, "lifecycle_module", return_value=core),
              patch.object(release, "pages", return_value=[owner_comment, bot_comment])):
            reservation = release.current_final_reservation(
                self.repo, 91, candidate, 800, 1, "f" * 40)
        self.assertIs(reservation, bot_comment)

    def test_real_disposition_json_keeps_batch_like_evidence_as_data(self):
        candidate_id = "c" * 64
        nested_valid = '<!-- fork-finding-batch:v1 {"schema":1} -->'
        nested_malformed = '<!-- fork-finding-batch:v1 {'
        evidence = ("The reviewed evidence quotes " + nested_valid + " and "
                    + nested_malformed)
        disposition = {
            "schema": 1, "candidate_id": candidate_id, "source_sha": "d" * 40,
            "findings": [{"finding_id": "carried:91:603", "status": "disproved",
                          "evidence": evidence}],
        }
        disposition_marker = "<!-- fork-review-disposition:v1 " + json.dumps(
            disposition, sort_keys=True, separators=(",", ":")) + " -->"
        comment = {
            "id": 108, "created_at": "2026-10-19T10:00:00Z",
            "updated_at": "2026-10-19T10:00:00Z",
            "user": {"login": "warelik", "type": "User"},
            "body": disposition_marker,
        }

        self.assertEqual(release._native_finding_batch_values(comment["body"]), [])
        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))
        with (patch.object(release, "pages", return_value=[comment]),
              patch.object(release, "lifecycle_module", return_value=core)):
            comments, findings, sources, prior = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

        self.assertEqual(comments, [comment])
        self.assertEqual(findings, [])
        self.assertEqual(sources, {})
        self.assertEqual(prior["carried:91:603"]["evidence"], evidence)
        self.assertIn(disposition_marker, release._owner_protocol_comment_body(
            "warelik", comment, cutoff=release.parse_utc(REVIEW_HISTORY_CUTOFF)))

    def test_outer_policy_pair_payload_is_opaque_to_batch_prefix_scanning(self):
        nested_valid = '<!-- fork-finding-batch:v1 {"schema":1} -->'
        nested_malformed = '<!-- fork-finding-batch:v1 {'
        candidate = {"repository": self.repo, "upstream_sha": "1" * 40,
                     "application_sha": "2" * 40, "configuration_sha": "3" * 40}
        candidate_id = "c" * 64
        policy_pair = {
            "schema": 1, "candidate": candidate, "candidateIdentity": candidate_id,
            "acceptedBaselineProof": {},
            "findingHistory": [{"finding_id": "review:91:603",
                                "body": nested_valid + " " + nested_malformed}],
            "findingDispositions": [],
            "reviewContexts": {"full": {"pr": 91}, "delta": {"pr": 92}},
            "configSha": "4" * 40, "proposalPr": 90,
            "proposalHeadSha": "5" * 40, "candidatePr": 91, "deltaPr": 92,
        }
        marker = "<!-- fork-policy-pair:v1 " + json.dumps(
            policy_pair, sort_keys=True, separators=(",", ":")) + " -->"
        comment = {"id": 109, "created_at": "2026-10-19T10:00:00Z",
                   "updated_at": "2026-10-19T10:00:00Z",
                   "user": {"login": "warelik", "type": "User"}, "body": marker}

        self.assertEqual(release._native_finding_batch_values(comment["body"]), [])
        protocol_body = release._owner_protocol_comment_body(
            "warelik", comment, cutoff=release.parse_utc(REVIEW_HISTORY_CUTOFF))
        self.assertEqual(release._marker_value(
            release.POLICY_PAIR_MARKER, protocol_body, "paired policy review context"),
            policy_pair)

        for malformed in (
                '<!-- fork-policy-pair:v1 {truncated -->',
                '<!-- fork-policy-pair:v1 {"schema":1,"schema":1} -->'):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(ValueError, "malformed"):
                    release._native_finding_batch_values(malformed)

    def test_actual_batch_and_disposition_work_in_either_outer_order(self):
        candidate_id = "c" * 64
        candidate = {"repository": self.repo}
        contexts = {"full": {"pr": 91}, "delta": {"pr": 92}}
        finding = {"finding_id": "review:91:603", "candidate_id": candidate_id,
                   "scope": "full", "source_sha": "d" * 40,
                   "native_id": 603, "body": "P1: preserved finding"}
        batch = "<!-- fork-finding-batch:v1 " + json.dumps({
            "schema": 1, "candidate_id": candidate_id, "candidate": candidate,
            "review_contexts": contexts, "findings": [finding],
        }, sort_keys=True, separators=(",", ":")) + " -->"
        disposition = "<!-- fork-review-disposition:v1 " + json.dumps({
            "schema": 1, "candidate_id": candidate_id, "source_sha": "d" * 40,
            "findings": [{"finding_id": finding["finding_id"], "status": "disproved",
                          "evidence": ("The exact source and regression disprove the report. "
                                       '<!-- fork-finding-batch:v1 {"schema":1} --> '
                                       "<!-- fork-finding-batch:v1 {")}],
        }, sort_keys=True, separators=(",", ":")) + " -->"
        core = types.SimpleNamespace(candidate_identity=Mock(return_value=candidate_id))

        for order in ((disposition, batch), (batch, disposition)):
            with self.subTest(order=order[0][:40]):
                comment = {
                    "id": 110, "created_at": "2026-10-19T10:00:00Z",
                    "updated_at": "2026-10-19T10:00:00Z",
                    "user": {"login": "warelik", "type": "User"},
                    "body": "\n".join(order),
                }
                with (patch.object(release, "pages", return_value=[comment]),
                      patch.object(release, "lifecycle_module", return_value=core)):
                    comments, findings, sources, prior = release.load_review_finding_history(
                        self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
                self.assertEqual(comments, [comment])
                self.assertEqual(findings, [finding])
                self.assertEqual(sources[candidate_id], {
                    "candidate": candidate, "review_contexts": contexts,
                })
                self.assertEqual(prior[finding["finding_id"]]["status"], "disproved")

    def test_finding_history_skips_retired_edits_but_blocks_updates_after_cutoff(self):
        retired = {"id": 98, "created_at": "2026-10-19T08:00:00Z",
                   "updated_at": "2026-10-19T08:30:00Z",
                   "user": {"login": "warelik", "type": "User"},
                   "body": "<!-- fork-finding-batch:v1 {truncated"}
        core = types.SimpleNamespace(candidate_identity=Mock())
        with (patch.object(release, "pages", return_value=[retired]),
              patch.object(release, "lifecycle_module", return_value=core)):
            _comments, findings, sources, dispositions = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
        self.assertEqual(findings, [])
        self.assertEqual(sources, {})
        self.assertEqual(dispositions, {})

        edited_after = {**retired, "updated_at": "2026-10-19T09:01:00Z",
                        "body": "The old native finding batch was removed."}
        with (patch.object(release, "pages", return_value=[edited_after]),
              self.assertRaisesRegex(ValueError, "was edited")):
            release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)

        ordinary = {"id": 99, "created_at": "2026-10-19T10:00:00Z",
                    "updated_at": "2026-10-19T10:00:00Z",
                    "user": {"login": "warelik", "type": "User"},
                    "body": "An unchanged ordinary owner comment."}
        with patch.object(release, "pages", return_value=[ordinary]):
            _comments, findings, sources, dispositions = release.load_review_finding_history(
                self.repo, 91, published_at=REVIEW_HISTORY_CUTOFF)
        self.assertEqual((findings, sources, dispositions), ([], {}, {}))

    def test_changed_native_review_inventory_blocks_history_collection(self):
        pull = {"number": 91, "updated_at": "2026-10-19T10:00:00Z", "state": "open",
                "head": {"sha": "a" * 40, "ref": "review/source",
                         "repo": {"full_name": self.repo}},
                "base": {"sha": "b" * 40, "ref": "review-base/source"}}
        proof = {"variable": {"value": json.dumps({"publication": {
            "published_at": "2026-10-19T09:00:00Z"}})}}
        inventories = iter(([pull], []))
        def pages(route):
            return next(inventories) if "/pulls?" in route else []
        core = types.SimpleNamespace(review_history=Mock())
        with patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "api", return_value=pull), \
                patch.object(release, "_resolved_review_commits", return_value={}), \
                patch.object(release, "lifecycle_module", return_value=core):
            with self.assertRaisesRegex(ValueError, "inventory changed"):
                release.native_review_finding_history(self.repo, {"repository": self.repo}, proof)
        core.review_history.assert_not_called()

    def test_stale_baseline_is_rejected_before_fetching_publication(self):
        endpoint = f"repos/{self.repo}/actions/variables/FORK_ACCEPTED_BASELINE"
        old = {"endpoint": endpoint, "variable": {"value": "old"}}
        with patch.object(release, "owner_token", return_value="fixture-token"), \
                patch.object(release, "api", return_value={"value": "new"}), \
                patch.object(release, "urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "baseline changed"):
                release.current_review_baseline(self.repo, old)
        urlopen.assert_not_called()

    def test_native_variable_patch_204_requires_exact_readback(self):
        candidate = {"repository": self.repo}
        publication = {"kind": "signed-repository", "id": 31,
                       "published_at": "2026-10-19T10:00:00Z", "metadata_sha256": "d" * 64}
        value = json.dumps({"schema": 1, "repository": self.repo, "candidate": candidate,
                            "publication": publication}, sort_keys=True, separators=(",", ":"))
        old = {"name": "FORK_ACCEPTED_BASELINE", "value": "old"}
        new = {"name": old["name"], "value": value, "created_at": "2026-10-19T09:00:00Z",
               "updated_at": "2026-10-19T11:00:00Z"}
        manifest = {"candidate": candidate, "candidateIdentity": "c" * 64,
                    "acceptedBaselineProof": {"variable": old}}
        core = types.SimpleNamespace(candidate_identity=Mock(return_value="c" * 64))
        with patch.object(release, "lifecycle_module", return_value=core), \
                patch.object(release, "verified_pages_baseline", return_value={
                    "publication": publication, "published_at": publication["published_at"]}), \
                patch.object(release, "api", side_effect=[old, None, new]) as api:
            release.advance_accepted_baseline(self.repo, manifest, {}, "fixture-token")
        self.assertEqual(api.call_count, 3)
        self.assertEqual(api.call_args_list[1].kwargs["method"], "PATCH")
        self.assertEqual(api.call_args_list[2].kwargs, {"token": "fixture-token"})

    def test_full_context_uses_native_git_data_commit_records(self):
        candidate = {"repository": self.repo, "application_sha": "a" * 40,
                     "configuration_sha": "d" * 40}
        request = {"id": 71, "user": {"login": "warelik", "type": "User"}, "body": "exact request",
                   "created_at": "2026-10-19T10:00:00Z", "updated_at": "2026-10-19T10:00:00Z"}
        with patch.object(release, "api", side_effect=lambda route: {"sha": route.rsplit("/", 1)[-1]}) as api:
            target = release._native_review_target(
                self.repo, {}, request, candidate, "full", "b" * 40, "c" * 40,
                "review/context", "review-base/upstream")
        self.assertEqual([call.args[0] for call in api.call_args_list], [
            f"repos/{self.repo}/git/commits/" + "a" * 40,
            f"repos/{self.repo}/git/commits/" + "d" * 40,
            f"repos/{self.repo}/git/commits/" + "b" * 40])
        self.assertEqual(set(target["source_git_data"]), {"application", "configuration", "review"})
        self.assertIs(target["application_commit"], target["source_git_data"]["application"])
        self.assertIs(target["review_commit"], target["source_git_data"]["review"])
        self.assertFalse(target["allow_closed"])
        self.assertEqual(target["request"], request)

    def test_delta_source_git_data_deduplicates_repeated_role_sha(self):
        candidate = {"repository": self.repo, "application_sha": "a" * 40,
                     "configuration_sha": "d" * 40}
        with patch.object(release, "api",
                          side_effect=lambda route: {"sha": route.rsplit("/", 1)[-1]}) as api:
            source = release.native_source_git_data(
                self.repo, candidate, candidate["configuration_sha"])
        self.assertEqual([call.args[0] for call in api.call_args_list], [
            f"repos/{self.repo}/git/commits/" + "a" * 40,
            f"repos/{self.repo}/git/commits/" + "d" * 40])
        self.assertIs(source["configuration"], source["review"])

    def test_bundle_receipt_uses_the_public_lock_bound_loader(self):
        verifier = Mock(return_value={"verified": True})
        loader = types.SimpleNamespace(validated_bundle=verifier)
        comments = [{"id": 8}]
        with patch.dict(sys.modules, {"maintenance": loader}), \
                patch.object(release, "owner_token", return_value="fixture-owner-token"), \
                patch.object(release, "pages", return_value=comments), \
                patch.object(release, "api", return_value={}) as api, \
                patch.object(release, "lifecycle_module", side_effect=AssertionError("wrapper bypassed")):
            self.assertTrue(release.validated_policy_bundle(self.repo, {"candidate": 1}, 91))
            callback = verifier.call_args.args[2]
            callback(f"repos/{self.repo}/pulls/91")
            with self.assertRaises(ValueError):
                callback("https://example.invalid/untrusted")
        self.assertEqual(verifier.call_args.args[:2], ({"candidate": 1}, comments))
        api.assert_called_once_with(f"repos/{self.repo}/pulls/91", token="fixture-owner-token")

    def test_verified_closed_context_is_reused_without_reopening(self):
        base, head = "a" * 40, "b" * 40
        pull = {"number": 91, "state": "closed", "body": "exact context",
                "base": {"sha": base, "ref": "review-base/base", "repo": {"full_name": self.repo}},
                "head": {"sha": head, "ref": "review/head", "repo": {"full_name": self.repo}}}
        identity = {"base_sha": base, "base_branch": "review-base/base",
                    "head_sha": head, "head_branch": "review/head"}
        self.assertFalse(release.review_pull_identity(self.repo, pull, **identity))
        with patch.object(release, "find_review_pull", return_value=pull), \
                patch.object(release, "api") as api:
            result = release.ensure_review_pull(
                self.repo, title="review", body=pull["body"], **identity, allow_closed=True)
        self.assertEqual(result["state"], "closed")
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
