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
disabled, avoiding an OS action in the test fixture. The last verified signed
production manifest records patch SHA-256
`c7b7de53fcf23d2c9d53733b0389ecbd59e752b2f323e991390f242df22d6515`.

The modern VM inventory endpoint is retained when the legacy format would omit
package records, including Snap packages. In that case a `FailedPrecondition`
from the modern endpoint does not trigger a partial legacy report; a host whose
endpoint supports only the legacy API may therefore fail to report inventory.

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

Supported server delivery uses the existing installer/updater and its explicit
`on`/`off` service state. After a verified package replacement, that recipe enables
and starts the service for `on`, and restarts an already active service to run the
new package. An unchanged-package check preserves the running process. State
`off` keeps the service stopped and disabled and blocks activation during package
staging. The RPM retains its systemd lifecycle macros; service activation remains
owned by the server recipe. A direct RPM installation outside that managed path
is not claimed to provide upstream's preset or first-install activation behavior.

The public adapter pins the private `warelik/machine-maintenance` lifecycle
module by exact commit and SHA-256 in `maintenance.lock.json`. Jobs that call
the shared lifecycle adapter acquire that revision with a read-only deploy key
and disable checkout credential persistence. The private source is used from
its temporary checkout; it is not copied into the RPM, artifact, or repository.

Application candidates receive two independent native reviews: the full review
reads the assembled patched Go source against the exact upstream commit, while
the delta review reads the changed downstream configuration or application
delta against the protected last-accepted baseline. Findings carry forward until
an owner-authenticated disposition identifies the exact repaired source and
code/regression evidence. Tests and dependency installation begin only after
both complete review lists are clean. The RPM recipe runs the mandatory Go
regressions once in the final build job; the workflow does not run
`check-upstream.sh` as a second test pass. A policy-only change skips RPM build
and preserves the published package provenance when all product/build inputs
match the signed baseline.

The application-attempt budget covers only the native `build-rpm` and `sign`
jobs. The separate `policy-validation` result is tracked by exact candidate,
run ID, and run attempt: an active unit waits, a failed unit blocks that exact
source, and one successful unit can be reused without repeating its tests.
Changing policy does not refund a started application attempt.

Build and signature artifacts carry source, workflow, run-attempt, and file-hash
receipts. An `already-validated` decision continues through metadata checks and
publication only after those receipts, the exact source identity, the signed
manifest, RPM, and RPM-MD signatures verify. A legacy artifact can be recovered
only from a run with a single native attempt; artifacts without enough exact
provenance stop publication and never trigger another application build or
signing run.

Policy adoption checks run the proposed CLI against trusted regressions in a
container without network access or credentials. The parser dependency is
installed before this check and mounted read-only with the trusted test inputs,
so the candidate cannot alter the parser used to judge its output. A native
regression checks that existing parser files and adjacent new files cannot be
written.

The paired-review final policy command imports the proposed release module in
that read-only sandbox before running the immutable trusted test suite against
it, then runs only proposed test files whose bytes are new or changed. Legacy
diagnostic commands keep their trusted-baseline behavior. For policy-only
migration, the final metadata guard can reuse a native exact-source receipt from
the private shared-validation run; it rechecks the full/delta review evidence
and private native workflow run before skipping that already-completed policy
test pass. In shared mode, subprocess output and container logs are discarded;
public logs report only the frozen public test filenames and pass/fail status.
This proof never permits an application build or artifact reuse.

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

This is a local diagnostic; the workflow runs the regressions once in the RPM
build job. If `UPSTREAM_SOURCE_DIR` points to an existing checkout, the script
copies it into temporary work before patching or formatting, leaving the caller's
tree unchanged. `TMPDIR` must be outside that source tree.

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
