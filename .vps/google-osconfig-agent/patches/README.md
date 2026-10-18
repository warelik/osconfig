# Google OS Config inventory package

This directory contains the downstream RPM recipe, minimal inventory fixes, and
GitHub maintenance workflow for GoogleCloudPlatform/osconfig. Upstream source is
kept intact and fetched as a complete, checksum-verified release. The workflow
template is installed byte-for-byte at
`.github/workflows/google-osconfig-agent-inventory.yml`. The root `AGENTS.md`
contains the fork-specific maintenance contract.

## Seed source and patch

The bootstrap source is upstream release `20261015.00`, commit
`f066b81252091d7e3f6be2611600e80aeaff7ce1`, archive SHA-256
`62d58fe4d3f833eb943ecb0d765c5dda3c846eff79dc2467680b35d12d9add7b`. The
ordered downstream patch fixes RPM `noarch` architecture reporting and ignores
DNF5 `replacing` rows in available-update inventory. It adds focused regressions
for both behaviors and makes the async task test explicitly dry-run with reboot
disabled, avoiding an OS action in the test fixture. Patch SHA-256:
`5b2ce54d5fd442558aaa87ae9a0f8b2aa2833c0f4a695471711f5af5be48cd0c`.

## Package and release boundary

`repository.conf` binds the repository to the dedicated primary signing
fingerprint `2730BEB4EE57C47CBD97B6A2697251684BDF2CE9`. Its minimum EVR
`0:20261015.00-1.vps1.fc44` is a lower bound for an acceptable fixed package;
it does not claim that this package has been built, signed, or published. The
workflow verifies exact source identity and review before signing and publication.
The private signing key is not part of this repository. This bootstrap commit
contains no RPM or repository metadata. CI, signature verification, publication,
and server delivery are distinct stages and need their own successful evidence.

The workflow uses public candidate branches and keeps build/review/publisher
policy repairs machine-maintained. It publishes only the package repository
artifacts, not server configuration, VM inventory, or credentials.

Policy adoption checks run the proposed CLI against trusted regressions in a
container without network access or credentials. The parser dependency is
installed before this check and mounted read-only with the trusted test inputs,
so the candidate cannot alter the parser used to judge its output. A native
regression checks that existing parser files and adjacent new files cannot be
written.

The signing job checks out the exact trusted workflow commit and executes its
signer, verifier, and disposable-key regression. Application repair artifacts
contain package inputs and built RPM data; they cannot replace those signing
scripts. The production key is supplied only to the signing step. Signing and
review-command failures enter the separate publisher repair flow.

The initial YAML parser comes from the trusted bootstrap requirements file.
Both parser requirement files pin the same exact PyYAML version and official
wheel SHA-256; proposed changes are checked before adoption. Candidate dependency
resolution uses `pip --require-hashes`, followed by offline installation and the
trusted regressions in a separate container without network access. The nested
upstream patch is excluded from the outer patch whitespace check, while other
package inputs retain that check.

## Local checks

Run the pinned-source regressions with:

```bash
bash .vps/google-osconfig-agent/patches/check-upstream.sh
```

Run the trusted release-gate tests with:

```bash
python3 -B -m unittest discover \
  -s .vps/google-osconfig-agent/patches/tests -p 'test_*.py' -v
```

A successful local check does not establish a public Actions run, signed
publication, or delivery to a VM.

2026-10-18: the complete publisher suite passed 74 tests. Its native isolated
policy check also passed, including the parser write-denial regression, exact
Action commit resolution, hashed wheel download, offline installation, and
checksum-verified actionlint. The earlier exact-commit review findings were
corrected; this changed commit still requires fresh native Codex review.

The next correction rejects custom signer shell/working-directory settings,
untrusted package URLs or repository overrides, alternate Action subdirectories,
and conditions that bypass the review gate. Normal package-name, runner, image
and timeout updates remain covered. The direct suite now passes 80 tests, and
the actual isolated policy check passes the native parser protection case too.
Review comments use their original reviewed commit identity because GitHub can
relocate an older inline comment to a newer head; a fresh clean review is still
required for the changed commit.
