"""The local upstream diagnostic must not modify its caller's source tree."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PATCH_DIR = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = PATCH_DIR / "check-upstream.sh"
SOURCE_FILES = (
    "packages/packages_linux.go",
    "packages/yum.go",
    "packages/yum_test.go",
    "agentendpoint/inventory.go",
    "agentendpoint/inventory_test.go",
    "agentendpoint/agentendpoint_test.go",
)


def write_executable(path, contents):
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def caller_tree(root):
    source = root / "caller-source"
    for relative in SOURCE_FILES:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("original source\n", encoding="utf-8")
        path.chmod(0o444)
    return source


def fake_commands(root):
    bin_dir = root / "fake-bin"
    bin_dir.mkdir()
    log_path = root / "command-log"
    write_executable(bin_dir / "git", "#!/usr/bin/env bash\nexit 0\n")
    write_executable(
        bin_dir / "patch",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'patch|%s|%s\\n' \"$PWD\" \"${1:-}\" >> \"$COMMAND_LOG\"\n"
        "if [[ \"${1:-}\" != --dry-run ]]; then printf 'patched\\n' >> packages/yum.go; fi\n",
    )
    write_executable(
        bin_dir / "gofmt",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'gofmt|%s\\n' \"$PWD\" >> \"$COMMAND_LOG\"\n"
        "printf 'formatted\\n' >> agentendpoint/inventory.go\n",
    )
    write_executable(
        bin_dir / "go",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'go|%s\\n' \"$PWD\" >> \"$COMMAND_LOG\"\n"
        "if [[ \"${FAKE_GO_FAILURE:-0}\" == 1 ]]; then exit 17; fi\n",
    )
    return bin_dir, log_path


class UpstreamSourceIsolationTests(unittest.TestCase):
    def run_check(self, root, source, *, go_fails=False, temp_root=None):
        bin_dir, log_path = fake_commands(root)
        temporary = temp_root or root / "tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment.update({
            "COMMAND_LOG": str(log_path),
            "FAKE_GO_FAILURE": "1" if go_fails else "0",
            "PATH": str(bin_dir) + os.pathsep + environment.get("PATH", ""),
            "TMPDIR": str(temporary),
            "UPSTREAM_SOURCE_DIR": str(source),
            "UPSTREAM_PATCH_FILE": str(PATCH_DIR / "osconfig-inventory.patch"),
        })
        result = subprocess.run(
            ["bash", str(CHECK_SCRIPT)], cwd=root, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return result, log_path

    def test_caller_source_stays_unchanged_when_copy_is_patched_and_formatted(self):
        for go_fails in (False, True):
            with self.subTest(go_fails=go_fails), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = caller_tree(root)
                original = {
                    relative: ((source / relative).read_bytes(),
                               (source / relative).stat().st_mode & 0o777)
                    for relative in SOURCE_FILES
                }

                result, log_path = self.run_check(root, source, go_fails=go_fails)

                self.assertEqual(result.returncode, 17 if go_fails else 0, result.stderr)
                self.assertEqual({
                    relative: ((source / relative).read_bytes(),
                               (source / relative).stat().st_mode & 0o777)
                    for relative in SOURCE_FILES
                }, original)
                events = log_path.read_text(encoding="utf-8").splitlines()
                workdirs = {event.split("|", 2)[1] for event in events}
                self.assertEqual(len(workdirs), 1)
                self.assertNotEqual(Path(next(iter(workdirs))), source)
                self.assertTrue(any(event.startswith("patch|") for event in events))
                self.assertTrue(any(event.startswith("gofmt|") for event in events))

    def test_tmpdir_inside_caller_source_is_rejected_before_working_on_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = caller_tree(root)
            original = {
                relative: ((source / relative).read_bytes(),
                           (source / relative).stat().st_mode & 0o777)
                for relative in SOURCE_FILES
            }

            result, log_path = self.run_check(root, source, temp_root=source)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TMPDIR must be outside UPSTREAM_SOURCE_DIR", result.stderr)
            self.assertEqual({
                relative: ((source / relative).read_bytes(),
                           (source / relative).stat().st_mode & 0o777)
                for relative in SOURCE_FILES
            }, original)
            self.assertFalse(log_path.exists())

    def test_symlinked_patch_target_is_rejected_without_writing_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = caller_tree(root)
            target = root / "external-target.go"
            target.write_text("external original\n", encoding="utf-8")
            symlink = source / "packages/yum.go"
            symlink.unlink()
            symlink.symlink_to(target)

            result, log_path = self.run_check(root, source)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Upstream patch target is missing or unsafe: packages/yum.go",
                          result.stderr)
            self.assertTrue(symlink.is_symlink())
            self.assertEqual(os.readlink(symlink), str(target))
            self.assertEqual(target.read_text(encoding="utf-8"), "external original\n")
            self.assertFalse(log_path.exists())


if __name__ == "__main__":
    unittest.main()
