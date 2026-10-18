# Machine-maintained Google OS Config fork

This repository follows upstream GoogleCloudPlatform/osconfig and carries only
the minimal fixes needed for Google OS Config inventory reporting. It is not an
independent product. Keep Patch and guest-policy behavior out of scope.

## Source and fixes

- Select one complete upstream release or exact supported commit and pin its
  source archive, commit, and checksum. Keep upstream source separate from the
  ordered downstream patch series.
- Rebase each patch onto the selected source while preserving new upstream
  behavior. Run the regression tests on the exact resulting commit.
- When upstream already fixes a defect, prove the regression passes on clean
  upstream without our product change, remove only the redundant product hunk,
  and keep the useful regression test.
- Review the exact SHA that passed tests. A changed SHA needs fresh tests and
  review. Resolve every real finding before publication; no priority-level
  exception weakens this gate.

## Automated maintenance

- GitHub Actions and native Codex tasks handle source refresh, patch repair,
  release-policy repair, build, signing, publication, and verification. Machines
  make ordinary changes and repair failures; a report or unpublished change is
  not a completed fix.
- Keep application patches and release-policy repairs separate. Immutable
  trusted CLI regressions exercise the proposed release program in an isolated
  no-network environment with fake GitHub/Git fixtures. Review its exact SHA,
  then selectively adopt only allowlisted files and dispatch a fresh trusted
  cycle.
- Bound each job and task by time and resources. If a window expires, a later
  scheduled run continues the same repair cycle with its history, current
  evidence, and a new diagnostic approach. Do not escalate or stop because of
  elapsed time or attempt count alone, and do not repeat an unchanged approach
  without new evidence.
- Ask the owner to decide only after evidence proves no simple correct fix is
  available, a permission must change, or the product scope must change. Report
  the exact evidence and consequence; elapsed time is not proof.
- Preserve exact source identity, tests, review, signing, repository trust, and
  package integrity. Never bypass a required gate or publish an unsigned RPM.
  GitHub publication does not deploy to a VM.
