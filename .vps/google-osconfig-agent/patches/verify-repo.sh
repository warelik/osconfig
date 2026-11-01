#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

candidate=${1:-}
repository=${2:-}
[[ $# == 2 && $candidate == /* && $repository == /* ]] || {
    echo 'Usage: verify-repo.sh /absolute/built-candidate /absolute/signed-repository-root' >&2
    exit 2
}
for command_name in gpg gpgconf rpm rpmkeys jq sha256sum mkdir mktemp rm find awk grep cut; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing signed repository verifier command: $command_name" >&2
        exit 1
    }
done
fingerprint=${OSCONFIG_RPM_SIGNING_FINGERPRINT:-}
expected_candidate=${EXPECTED_CANDIDATE_SHA:-}
expected_upstream=${EXPECTED_UPSTREAM_SHA:-}
expected_patch=${EXPECTED_PATCH_SHA:-}
[[ $fingerprint =~ ^([A-F0-9]{40}|[A-F0-9]{64})$ &&
   $expected_candidate =~ ^[0-9a-f]{40}$ && $expected_upstream =~ ^[0-9a-f]{40}$ &&
   $expected_patch =~ ^[0-9a-f]{64}$ ]] || {
    echo 'Signed repository verifier received incomplete candidate identity' >&2
    exit 1
}
rpm_root=$repository/rpm
manifest=$rpm_root/manifest.json
key_file=$rpm_root/RPM-GPG-KEY-google-osconfig-agent
repomd=$rpm_root/repodata/repomd.xml
repomd_sig=$rpm_root/repodata/repomd.xml.asc
manifest_sig=$rpm_root/manifest.json.asc
for file in "$manifest" "$key_file" "$repomd" "$repomd_sig" "$manifest_sig"; do
    [[ -f $file && ! -L $file ]] || { echo "Missing or unsafe signed repository file: $file" >&2; exit 1; }
done
jq -e --arg candidate "$expected_candidate" --arg upstream "$expected_upstream" --arg patch "$expected_patch" --arg fingerprint "$fingerprint" '
  .candidateSha == $candidate and .upstreamCommit == $upstream
  and .patchSha256 == $patch and .signingFingerprint == $fingerprint
  and (.signedRpmSha256 | test("^[0-9a-f]{64}$"))
  and (.rpmHeaderSha256 | test("^[0-9a-f]{64}$"))
  and (.rpmFilename | test("^google-osconfig-agent-[A-Za-z0-9.+~^_-]+-[A-Za-z0-9.+~^_-]+[.]x86_64[.]rpm$"))
  and (.packageEvr | test("^0:[^[:space:]]+$"))
  and (.architecture == "x86_64")
' "$manifest" >/dev/null || { echo 'Signed repository manifest does not identify the reviewed candidate' >&2; exit 1; }
mapfile -t packages < <(find "$rpm_root" -maxdepth 1 -type f -name 'google-osconfig-agent-*.rpm' -print)
[[ ${#packages[@]} == 1 ]] || { echo 'Signed repository must contain exactly one agent RPM' >&2; exit 1; }
rpm_file=${packages[0]}
[[ ! -L $rpm_file ]] || { echo 'Signed repository RPM is a symlink' >&2; exit 1; }
[[ $(basename "$rpm_file") == "$(jq -er .rpmFilename "$manifest")" ]] || {
    echo 'Signed repository RPM filename differs from its manifest' >&2
    exit 1
}
rpm_hash=$(sha256sum "$rpm_file" | cut -d' ' -f1)
[[ $rpm_hash == "$(jq -er .signedRpmSha256 "$manifest")" ]] || {
    echo 'Published RPM SHA-256 differs from the signed manifest' >&2
    exit 1
}
identity=$(rpm -qp --qf '%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}\n' "$rpm_file")
IFS='|' read -r name evr arch <<< "$identity"
[[ $name == google-osconfig-agent && $evr == "$(jq -er .packageEvr "$manifest")" && $arch == x86_64 ]] || {
    echo 'Published RPM identity differs from the signed manifest' >&2
    exit 1
}
header_hash=$(rpm -qp --qf '%{SHA256HEADER}' "$rpm_file")
[[ ${header_hash,,} == "$(jq -er .rpmHeaderSha256 "$manifest")" ]] || {
    echo 'Published RPM header identity differs from the signed manifest' >&2
    exit 1
}

work=$(mktemp -d "${TMPDIR:-/tmp}/google-osconfig-agent-verify.XXXXXX") || {
    echo 'Unable to create isolated signature verifier' >&2
    exit 1
}
cleanup() { gpgconf --homedir "$work/gnupg" --kill all >/dev/null 2>&1 || :; rm -rf -- "$work"; }
trap cleanup EXIT
export GNUPGHOME=$work/gnupg
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --import "$key_file" >/dev/null 2>&1 || { echo 'Unable to import repository public key' >&2; exit 1; }
actual_fingerprint=$(gpg --batch --with-colons --list-keys |
    awk -F: '$1 == "pub" { primary=1; next } primary && $1 == "fpr" { print toupper($10); primary=0 }') || {
    echo 'Unable to inspect repository public key fingerprints' >&2; exit 1;
}
# An extra imported primary would also become trusted by gpg and the private RPM DB.
# Require exactly the pinned primary; its authenticated signing subkeys remain valid.
[[ $actual_fingerprint == "$fingerprint" ]] || { echo 'Repository public key fingerprint mismatch' >&2; exit 1; }
gpg --batch --verify "$manifest_sig" "$manifest" >/dev/null 2>&1 || { echo 'Manifest signature verification failed' >&2; exit 1; }
gpg --batch --verify "$repomd_sig" "$repomd" >/dev/null 2>&1 || { echo 'RPM-MD metadata signature verification failed' >&2; exit 1; }
rpmdb=$work/rpmdb
mkdir -m 0700 "$rpmdb"
rpm --dbpath "$rpmdb" --initdb
rpm --dbpath "$rpmdb" --import "$key_file"
rpmkeys --dbpath "$rpmdb" --checksig --verbose "$rpm_file" > "$work/rpm-check.log" 2>&1 || {
    cat "$work/rpm-check.log" >&2
    echo 'Published RPM signature verification failed' >&2
    exit 1
}
grep -Eiq 'signature, .*: OK$' "$work/rpm-check.log" || {
    cat "$work/rpm-check.log" >&2
    echo 'RPM verifier did not report complete signature and digest success' >&2
    exit 1
}
printf 'PASS: signed RPM, repomd, manifest and exact candidate identity verified (%s %s)\n' "$name" "$evr"
