#!/usr/bin/env bash
# Native Fedora signing regression using disposable keys and an already built RPM.
set -Eeuo pipefail
umask 077
scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
built=${1:-}
[[ $# == 1 && $built == /* && -f $built/candidate-manifest.json ]] || {
    echo 'Usage: signing.sh /absolute/built-candidate' >&2; exit 2;
}
work=$(mktemp -d /var/tmp/osconfig-signing-test.XXXXXX)
cleanup() { gpgconf --homedir "$work/gnupg" --kill all >/dev/null 2>&1 || :; rm -rf -- "$work"; }
trap cleanup EXIT
export HOME=$work/home XDG_CONFIG_HOME=$work/config XDG_DATA_HOME=$work/data
export XDG_CACHE_HOME=$work/cache XDG_STATE_HOME=$work/state XDG_RUNTIME_DIR=$work/run
export XDG_CONFIG_DIRS=$work/config-dirs XDG_DATA_DIRS=$work/data-dirs TMPDIR=$work/tmp GNUPGHOME=$work/gnupg
mkdir -m 0700 "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" \
    "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_DIRS" "$XDG_DATA_DIRS" "$TMPDIR" "$GNUPGHOME"
cd "$work"
unset OSCONFIG_RPM_SIGNING_PRIVATE_KEY
export EXPECTED_CANDIDATE_SHA EXPECTED_UPSTREAM_SHA EXPECTED_PATCH_SHA
EXPECTED_CANDIDATE_SHA=$(jq -er .candidateSha "$built/candidate-manifest.json")
EXPECTED_UPSTREAM_SHA=$(jq -er .upstreamCommit "$built/candidate-manifest.json")
EXPECTED_PATCH_SHA=$(jq -er .patchSha256 "$built/candidate-manifest.json")
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
    'Disposable verifier test <signing-test@invalid.example>' rsa2048 sign 1d >"$work/keygen.log" 2>&1
fingerprint=$(gpg --batch --with-colons --list-keys |
    awk -F: '$1=="pub" {primary=1;next} primary && $1=="fpr" {print toupper($10);exit}')
[[ $fingerprint =~ ^[A-F0-9]{40}$ ]]
export OSCONFIG_RPM_SIGNING_FINGERPRINT=$fingerprint
OSCONFIG_RPM_SIGNING_PRIVATE_KEY=$(gpg --batch --armor --export-secret-keys "$fingerprint") \
    bash "$scripts/sign-repo.sh" "$built" "$work/repository"
bash "$scripts/verify-repo.sh" "$built" "$work/repository"
key=$work/repository/rpm/RPM-GPG-KEY-google-osconfig-agent
cp "$key" "$work/original-key"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
    'Foreign verifier test <foreign-test@invalid.example>' rsa2048 sign 1d >"$work/foreign-keygen.log" 2>&1
foreign=$(gpg --batch --with-colons --list-keys |
    awk -F: -v expected="$fingerprint" '$1=="pub" {primary=1;next} primary && $1=="fpr" {primary=0; if(toupper($10)!=expected) print toupper($10)}')
[[ $foreign =~ ^[A-F0-9]{40}$ && $foreign != "$fingerprint" ]]
gpg --batch --armor --export "$foreign" > "$work/foreign-key"
reject() {
    local reason=$1
    if bash "$scripts/verify-repo.sh" "$built" "$work/repository" >"$work/rejected.log" 2>&1; then
        echo "Verifier accepted invalid repository: $reason" >&2; exit 1;
    fi
    grep -Fq "$reason" "$work/rejected.log" || { cat "$work/rejected.log" >&2; exit 1; }
}
cp "$work/foreign-key" "$key"
reject 'Repository public key fingerprint mismatch'
cat "$work/original-key" "$work/foreign-key" > "$key"
reject 'Repository public key fingerprint mismatch'
cp "$work/original-key" "$key"
# A valid, pinned signature on the manifest cannot replace the mandatory RPM signature.
mapfile -t packages < <(find "$work/repository/rpm" -maxdepth 1 -name '*.rpm' -type f)
[[ ${#packages[@]} == 1 ]]
rpm --delsign "${packages[0]}"
hash=$(sha256sum "${packages[0]}" | cut -d' ' -f1)
jq --arg hash "$hash" '.signedRpmSha256=$hash' "$work/repository/rpm/manifest.json" > "$work/unsigned-manifest"
mv "$work/unsigned-manifest" "$work/repository/rpm/manifest.json"
gpg --batch --yes --armor --local-user "$fingerprint" --detach-sign \
    --output "$work/repository/rpm/manifest.json.asc" "$work/repository/rpm/manifest.json"
reject 'RPM verifier did not report complete signature and digest success'
echo 'PASS: real signed RPM/metadata; wrong key, extra primary key and unsigned RPM rejected'
