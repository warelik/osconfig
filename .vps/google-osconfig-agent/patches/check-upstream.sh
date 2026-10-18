#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
patch_file=${UPSTREAM_PATCH_FILE:-$here/osconfig-inventory.patch}
work=$(mktemp -d "${TMPDIR:-/tmp}/google-osconfig-agent-upstream.XXXXXX") || {
    echo 'Unable to create upstream patch test directory' >&2
    exit 1
}
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

for command_name in git patch go gofmt; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing command: $command_name" >&2
        exit 1
    }
done

if [[ -n ${UPSTREAM_SOURCE_DIR:-} ]]; then
    [[ $UPSTREAM_SOURCE_DIR == /* && -d $UPSTREAM_SOURCE_DIR && ! -L $UPSTREAM_SOURCE_DIR ]] || {
        echo 'UPSTREAM_SOURCE_DIR must name an absolute, regular directory' >&2
        exit 1
    }
    source_dir=$UPSTREAM_SOURCE_DIR
else
    bash "$here/prepare-source.sh" --locked "$work/source-input" >/dev/null
    source_dir=$work/source-input/upstream
fi
(
    cd -- "$source_dir"
    patch --dry-run --fuzz=0 -p1 -i "$patch_file"
    patch --fuzz=0 -p1 -i "$patch_file"
    gofmt -w packages/packages_linux.go packages/yum.go packages/yum_test.go agentendpoint/inventory.go agentendpoint/inventory_test.go agentendpoint/agentendpoint_test.go
    go test -count=1 -timeout=5m ./packages ./agentendpoint
)
printf '%s\n' 'PASS: pinned Google OS Config inventory patch and regression tests'
