#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
patch_file=${UPSTREAM_PATCH_FILE:-$here/osconfig-inventory.patch}
source_dir=
if [[ -n ${UPSTREAM_SOURCE_DIR:-} ]]; then
    [[ $UPSTREAM_SOURCE_DIR == /* && -d $UPSTREAM_SOURCE_DIR && ! -L $UPSTREAM_SOURCE_DIR ]] || {
        echo 'UPSTREAM_SOURCE_DIR must name an absolute, regular directory' >&2
        exit 1
    }
    source_dir=$(cd -- "$UPSTREAM_SOURCE_DIR" && pwd -P) || {
        echo 'Unable to resolve UPSTREAM_SOURCE_DIR' >&2
        exit 1
    }
fi

temporary_root=${TMPDIR:-/tmp}
[[ -d $temporary_root ]] || {
    echo 'TMPDIR must name an existing directory' >&2
    exit 1
}
temporary_root=$(cd -- "$temporary_root" && pwd -P) || {
    echo 'Unable to resolve TMPDIR' >&2
    exit 1
}
if [[ -n $source_dir && ( $source_dir == / || $temporary_root == "$source_dir" ||
      $temporary_root == "$source_dir/"* ) ]]; then
    echo 'TMPDIR must be outside UPSTREAM_SOURCE_DIR' >&2
    exit 1
fi

for command_name in chmod cp git go gofmt mkdir mktemp patch rm; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing command: $command_name" >&2
        exit 1
    }
done

work=$(mktemp -d "${temporary_root%/}/google-osconfig-agent-upstream.XXXXXX") || {
    echo 'Unable to create upstream patch test directory' >&2
    exit 1
}
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

write_targets=(
    packages/packages_linux.go packages/yum.go packages/yum_test.go
    agentendpoint/inventory.go agentendpoint/inventory_test.go
    agentendpoint/agentendpoint_test.go
)
if [[ -n $source_dir ]]; then
    mkdir -p -- "$work/source-input"
    cp -a -- "$source_dir" "$work/source-input/upstream"
    source_dir=$work/source-input/upstream
    chmod -R u+rwX -- "$source_dir"
else
    bash "$here/prepare-source.sh" --locked "$work/source-input" >/dev/null
    source_dir=$work/source-input/upstream
fi
for directory in packages agentendpoint; do
    [[ -d "$source_dir/$directory" && ! -L "$source_dir/$directory" ]] || {
        echo "Upstream patch target directory is missing or unsafe: $directory" >&2
        exit 1
    }
done
for relative in "${write_targets[@]}"; do
    [[ -f "$source_dir/$relative" && ! -L "$source_dir/$relative" ]] || {
        echo "Upstream patch target is missing or unsafe: $relative" >&2
        exit 1
    }
done
(
    cd -- "$source_dir"
    patch --dry-run --fuzz=0 -p1 -i "$patch_file"
    patch --fuzz=0 -p1 -i "$patch_file"
    gofmt -w "${write_targets[@]}"
    go test -count=1 -timeout=5m ./packages ./agentendpoint
)
printf '%s\n' 'PASS: pinned Google OS Config inventory patch and regression tests'
