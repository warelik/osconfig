#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
candidate=${1:-}
output=${2:-}
[[ $# == 2 && $candidate == /* && $output == /* ]] || {
    echo 'Usage: build-rpm.sh /absolute/candidate-directory /absolute/output-directory' >&2
    exit 2
}
for command_name in go rpmbuild sha256sum tar mkdir mktemp rm cp rpm patch gofmt jq; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing RPM build command: $command_name" >&2
        exit 1
    }
done
release=${VPS_RPM_RELEASE:-1.vps1}
[[ $release =~ ^[0-9]+\.vps[0-9]+$ ]] || { echo 'VPS_RPM_RELEASE is invalid' >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/google-osconfig-agent-rpm.XXXXXX") || {
    echo 'Unable to create RPM build directory' >&2
    exit 1
}
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

lock=$candidate/source.lock
archive=$candidate/source.tar.gz
patch_file=$candidate/osconfig-inventory.patch
spec_file=$candidate/google-osconfig-agent.spec
vendor_config=$candidate/go-vendor-tools.toml
candidate_manifest=$candidate/candidate-manifest.json
[[ -f $lock && ! -L $lock && -f $archive && ! -L $archive &&
   -f $patch_file && ! -L $patch_file && -f $spec_file && ! -L $spec_file &&
   -f $vendor_config && ! -L $vendor_config && -f $candidate_manifest && ! -L $candidate_manifest ]] || {
    echo 'Candidate package inputs are incomplete or unsafe' >&2
    exit 1
}
jq -e '
  type == "object"
  and (.tag | type == "string" and test("^[0-9]{8}\\.[0-9]{2}$"))
  and (.commit | type == "string" and test("^[0-9a-f]{40}$"))
  and (.archiveSha256 | type == "string" and test("^[0-9a-f]{64}$"))
' "$lock" >/dev/null || { echo 'Invalid candidate source.lock' >&2; exit 1; }
tag=$(jq -er .tag "$lock")
commit=$(jq -er .commit "$lock")
archive_sha=$(jq -er .archiveSha256 "$lock")
actual=$(sha256sum "$archive" | cut -d' ' -f1)
[[ $actual == "$archive_sha" ]] || { echo 'Candidate upstream archive checksum mismatch' >&2; exit 1; }
patch_sha=$(sha256sum "$patch_file" | cut -d' ' -f1)
spec_sha=$(sha256sum "$spec_file" | cut -d' ' -f1)
jq -e --arg commit "$commit" --arg archive "$archive_sha" --arg patch "$patch_sha" --arg spec "$spec_sha" '
  .upstreamCommit == $commit
  and .upstreamArchiveSha256 == $archive
  and .patchSha256 == $patch
  and .specSha256 == $spec
  and (.candidateSha | test("^[0-9a-f]{40}$"))
  and (.candidatePr | type == "number" and . > 0)
' "$candidate_manifest" >/dev/null || { echo 'Candidate manifest does not match reviewed source inputs' >&2; exit 1; }

source_dir=$work/osconfig-$tag
mkdir "$source_dir"
tar -xzf "$archive" --strip-components=1 -C "$source_dir"
patched_dir=$work/osconfig-$tag-patched
cp -a -- "$source_dir" "$patched_dir"
patch --dry-run --fuzz=0 -p1 -d "$patched_dir" -i "$patch_file"
patch --fuzz=0 -p1 -d "$patched_dir" -i "$patch_file"
gofmt -w "$patched_dir/packages/yum.go" "$patched_dir/packages/yum_test.go" \
    "$patched_dir/agentendpoint/inventory.go" "$patched_dir/agentendpoint/inventory_test.go" \
    "$patched_dir/agentendpoint/agentendpoint_test.go"
(
    cd "$patched_dir"
    go test -count=1 -timeout=5m ./packages ./agentendpoint
    go mod vendor
)

mkdir -p "$output" "$work/rpmbuild/SOURCES" "$work/rpmbuild/SPECS"
tar -czf "$work/rpmbuild/SOURCES/osconfig-$tag.tar.gz" -C "$work" "osconfig-$tag"
tar -cjf "$work/rpmbuild/SOURCES/osconfig-$tag-vendor.tar.bz2" -C "$patched_dir" vendor
cp -- "$spec_file" "$work/rpmbuild/SPECS/google-osconfig-agent.spec"
cp -- "$patch_file" "$work/rpmbuild/SOURCES/osconfig-inventory.patch"
cp -- "$vendor_config" "$work/rpmbuild/SOURCES/go-vendor-tools.toml"

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1}
rpmbuild -ba \
    --define "_topdir $work/rpmbuild" \
    --define "upstream_version $tag" \
    --define "vps_release $release" \
    "$work/rpmbuild/SPECS/google-osconfig-agent.spec"

shopt -s nullglob
rpms=("$work/rpmbuild/RPMS/x86_64/google-osconfig-agent-"[0-9]*.rpm)
[[ ${#rpms[@]} == 1 ]] || { echo 'RPM build did not produce exactly one x86_64 agent package' >&2; exit 1; }
rpm_file=${rpms[0]}
identity=$(rpm -qp --qf '%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}\n' "$rpm_file")
IFS='|' read -r name evr arch <<< "$identity"
[[ $name == google-osconfig-agent && $arch == x86_64 &&
   $evr == "0:$tag-$release.fc44" ]] || {
    echo "Unexpected built package identity: $identity" >&2
    exit 1
}
rpm -qpl "$rpm_file" > "$work/package-files.txt"
grep -qx '/usr/bin/google_osconfig_agent' "$work/package-files.txt"
grep -qx '/usr/lib/systemd/system/google-osconfig-agent.service' "$work/package-files.txt"
if grep -Eq '(^|/)(etc|var/lib)/|tools\\.state|os-config.inventory' "$work/package-files.txt"; then
    echo 'Built package contains server config or runtime inventory data' >&2
    exit 1
fi

mkdir -p "$output/rpm"
cp -- "$rpm_file" "$output/rpm/"
rpm_hash=$(sha256sum "$output/rpm/$(basename "$rpm_file")" | cut -d' ' -f1)
jq -n \
    --arg upstreamTag "$tag" --arg upstreamCommit "$commit" \
    --arg upstreamArchiveSha256 "$archive_sha" --arg patchSha256 "$patch_sha" \
    --arg specSha256 "$spec_sha" --arg rpmSha256 "$rpm_hash" \
    --arg packageEvr "$evr" --arg architecture "$arch" \
    '{upstreamTag:$upstreamTag,upstreamCommit:$upstreamCommit,
      upstreamArchiveSha256:$upstreamArchiveSha256,patchSha256:$patchSha256,
      specSha256:$specSha256,rpmSha256:$rpmSha256,packageEvr:$packageEvr,
      architecture:$architecture}' > "$output/build-manifest.json"
jq -s '.[0] * .[1]' "$candidate_manifest" "$output/build-manifest.json" \
    > "$output/candidate-manifest.json"
rm -- "$output/build-manifest.json"
printf 'Built %s %s %s\n' "$name" "$evr" "$arch"
