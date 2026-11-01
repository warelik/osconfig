#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

candidate=${1:-}
output=${2:-}
[[ $# == 2 && $candidate == /* && $output == /* ]] || {
    echo 'Usage: sign-repo.sh /absolute/built-candidate /absolute/pages-root' >&2
    exit 2
}
for command_name in createrepo_c gpg gpgconf rpmsign rpm rpmkeys jq sha256sum mkdir mktemp rm cp find awk grep cut; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing RPM signing command: $command_name" >&2
        exit 1
    }
done
[[ -n ${OSCONFIG_RPM_SIGNING_PRIVATE_KEY:-} ]] || {
    echo 'OSCONFIG_RPM_SIGNING_PRIVATE_KEY Actions secret is not configured; refusing unsigned publication' >&2
    exit 1
}
fingerprint=${OSCONFIG_RPM_SIGNING_FINGERPRINT:-}
[[ $fingerprint =~ ^([A-F0-9]{40}|[A-F0-9]{64})$ ]] || {
    echo 'OSCONFIG_RPM_SIGNING_FINGERPRINT Actions variable is missing or invalid' >&2
    exit 1
}
expected_candidate=${EXPECTED_CANDIDATE_SHA:-}
expected_upstream=${EXPECTED_UPSTREAM_SHA:-}
expected_patch=${EXPECTED_PATCH_SHA:-}
[[ $expected_candidate =~ ^[0-9a-f]{40}$ && $expected_upstream =~ ^[0-9a-f]{40}$ &&
   $expected_patch =~ ^[0-9a-f]{64}$ ]] || {
    echo 'The signer did not receive the exact reviewed candidate identity' >&2
    exit 1
}
jq -e '
  (.upstreamCommit | test("^[0-9a-f]{40}$"))
  and (.patchSha256 | test("^[0-9a-f]{64}$"))
  and (.rpmSha256 | test("^[0-9a-f]{64}$"))
  and (.packageEvr | test("^0:[^[:space:]]+$"))
  and (.candidateSha | test("^[0-9a-f]{40}$"))
  and (.candidatePr | type == "number" and . > 0)
  and (.architecture == "x86_64")
' "$candidate/candidate-manifest.json" >/dev/null || {
    echo 'Invalid build candidate manifest' >&2
    exit 1
}
jq -e --arg candidate "$expected_candidate" --arg upstream "$expected_upstream" --arg patch "$expected_patch" '
  .candidateSha == $candidate and .upstreamCommit == $upstream and .patchSha256 == $patch
' "$candidate/candidate-manifest.json" >/dev/null || {
    echo 'RPM artifact does not match the tested, reviewed exact-SHA candidate' >&2
    exit 1
}
mapfile -t packages < <(find "$candidate/rpm" -maxdepth 1 -type f -name 'google-osconfig-agent-*.rpm' -print)
[[ ${#packages[@]} == 1 ]] || { echo 'Expected exactly one RPM to sign' >&2; exit 1; }
rpm_file=${packages[0]}
hash=$(sha256sum "$rpm_file" | cut -d' ' -f1)
[[ $hash == "$(jq -er .rpmSha256 "$candidate/candidate-manifest.json")" ]] || {
    echo 'Built RPM SHA-256 does not match the reviewed manifest' >&2
    exit 1
}
identity=$(rpm -qp --qf '%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}\n' "$rpm_file")
IFS='|' read -r name evr arch <<< "$identity"
[[ $name == google-osconfig-agent &&
   $evr == "$(jq -er .packageEvr "$candidate/candidate-manifest.json")" &&
   $arch == x86_64 ]] || { echo 'Built RPM identity does not match the reviewed manifest' >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/google-osconfig-agent-sign.XXXXXX") || {
    echo 'Unable to create RPM signing directory' >&2
    exit 1
}
cleanup() { gpgconf --homedir "$work/gnupg" --kill all >/dev/null 2>&1 || :; rm -rf -- "$work"; }
trap cleanup EXIT
export GNUPGHOME=$work/gnupg
mkdir -m 0700 "$GNUPGHOME"
printf '%s\n' "$OSCONFIG_RPM_SIGNING_PRIVATE_KEY" | gpg --batch --import >/dev/null 2>&1 || {
    echo 'Unable to import the configured RPM signing key' >&2
    exit 1
}
unset OSCONFIG_RPM_SIGNING_PRIVATE_KEY
actual_fingerprint=$(gpg --batch --with-colons --list-keys "$fingerprint" |
    awk -F: '$1 == "pub" { primary=1; next } primary && $1 == "fpr" { print toupper($10); exit }')
[[ $actual_fingerprint == "$fingerprint" ]] || {
    echo 'Configured private key fingerprint does not match the required fingerprint' >&2
    exit 1
}

rm -rf -- "$output"
mkdir -p "$output/rpm"
cp -- "$rpm_file" "$output/rpm/"
key_file=$output/rpm/RPM-GPG-KEY-google-osconfig-agent
gpg --batch --armor --export "$fingerprint" > "$key_file"
[[ -s $key_file ]] || { echo 'Unable to export the public signing key' >&2; exit 1; }

rpmsign --define "_gpg_name $fingerprint" --addsign "$output/rpm/$(basename "$rpm_file")"
rpmdb=$work/rpmdb
mkdir -m 0700 "$rpmdb"
rpm --dbpath "$rpmdb" --initdb
rpm --dbpath "$rpmdb" --import "$key_file"
rpmkeys --dbpath "$rpmdb" --checksig --verbose "$output/rpm/$(basename "$rpm_file")" > "$work/rpm-check.log" 2>&1 || {
    cat "$work/rpm-check.log" >&2
    echo 'RPM signature verification failed' >&2
    exit 1
}
grep -Eiq 'signature, .*: OK$' "$work/rpm-check.log" || {
    cat "$work/rpm-check.log" >&2
    echo 'RPM verifier did not report a complete signature and digest success' >&2
    exit 1
}

createrepo_c --checksum sha256 --unique-md-filenames "$output/rpm"
gpg --batch --yes --armor --local-user "$fingerprint" \
    --detach-sign --output "$output/rpm/repodata/repomd.xml.asc" \
    "$output/rpm/repodata/repomd.xml"
gpg --batch --verify "$output/rpm/repodata/repomd.xml.asc" \
    "$output/rpm/repodata/repomd.xml" >/dev/null 2>&1 || {
    echo 'RPM-MD repomd.xml signature verification failed' >&2
    exit 1
}

signed_hash=$(sha256sum "$output/rpm/$(basename "$rpm_file")" | cut -d' ' -f1)
rpm_filename=$(basename "$rpm_file")
[[ $rpm_filename =~ ^google-osconfig-agent-[A-Za-z0-9.+~^_-]+-[A-Za-z0-9.+~^_-]+\.x86_64\.rpm$ ]] || {
    echo 'Built RPM filename is outside the supported package identity' >&2
    exit 1
}
rpm_header_sha=$(rpm -qp --qf '%{SHA256HEADER}' "$output/rpm/$rpm_filename")
[[ $rpm_header_sha =~ ^[a-fA-F0-9]{64}$ ]] || {
    echo 'RPM header does not expose a SHA-256 package identity' >&2
    exit 1
}
jq --arg fingerprint "$fingerprint" --arg signedRpmSha256 "$signed_hash" \
    --arg rpmFilename "$rpm_filename" --arg rpmHeaderSha256 "${rpm_header_sha,,}" \
    '. + {signingFingerprint:$fingerprint,signedRpmSha256:$signedRpmSha256,
          rpmFilename:$rpmFilename,rpmHeaderSha256:$rpmHeaderSha256}' \
    "$candidate/candidate-manifest.json" > "$output/rpm/manifest.json"
gpg --batch --yes --armor --local-user "$fingerprint" \
    --detach-sign --output "$output/rpm/manifest.json.asc" \
    "$output/rpm/manifest.json"
gpg --batch --verify "$output/rpm/manifest.json.asc" \
    "$output/rpm/manifest.json" >/dev/null 2>&1 || {
    echo 'Candidate manifest signature verification failed' >&2
    exit 1
}
printf 'Signed package repository verified: %s %s, fingerprint %s\n' "$name" "$evr" "$fingerprint"
