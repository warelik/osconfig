#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
mode=${1:-}
output=${2:-}
[[ $# == 2 && ( $mode == --locked || $mode == --latest ) && $output == /* ]] || {
    echo 'Usage: prepare-source.sh --locked|--latest /absolute/output-directory' >&2
    exit 2
}
for command_name in curl git jq mkdir mktemp rm sha256sum tar; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing command: $command_name" >&2
        exit 1
    }
done

mkdir -p -- "$output"
work=$(mktemp -d "${TMPDIR:-/tmp}/google-osconfig-agent-source.XXXXXX") || {
    echo 'Unable to create source preparation directory' >&2
    exit 1
}
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

if [[ $mode == --locked ]]; then
    lock=$here/source.lock
else
    [[ -n ${GITHUB_TOKEN:-} ]] || {
        echo 'GITHUB_TOKEN is required to resolve the latest upstream release without an unauthenticated API limit' >&2
        exit 1
    }
    [[ $GITHUB_TOKEN != *$'\n'* && $GITHUB_TOKEN != *$'\r'* ]] || {
        echo 'Invalid GITHUB_TOKEN value' >&2
        exit 1
    }
    printf 'Authorization: Bearer %s\nAccept: application/vnd.github+json\n' "$GITHUB_TOKEN" > "$work/github.headers"
    chmod 0600 "$work/github.headers"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --header "@$work/github.headers" \
        https://api.github.com/repos/GoogleCloudPlatform/osconfig/releases/latest \
        -o "$work/latest-release.json"
    tag=$(jq -er '.tag_name | select(type == "string" and test("^[0-9]{8}\\.[0-9]{2}$"))' "$work/latest-release.json") || {
        echo 'The latest upstream release tag is not a supported OS Config release version' >&2
        exit 1
    }
    git -c protocol.version=2 ls-remote https://github.com/GoogleCloudPlatform/osconfig.git \
        "refs/tags/$tag" "refs/tags/$tag^{}" > "$work/tag-refs"
    commit=$(awk -v peeled="refs/tags/$tag^{}" -v direct="refs/tags/$tag" \
        '$2 == peeled { print $1; found=1; exit } $2 == direct { direct_sha=$1 } END { if (!found && direct_sha != "") print direct_sha }' \
        "$work/tag-refs")
    [[ $commit =~ ^[0-9a-f]{40}$ ]] || {
        echo 'Unable to resolve the latest upstream release tag to one commit' >&2
        exit 1
    }
    archive_url=https://codeload.github.com/GoogleCloudPlatform/osconfig/tar.gz/$commit
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --retry-delay 1 "$archive_url" -o "$output/source.tar.gz"
    archive_sha=$(sha256sum "$output/source.tar.gz" | cut -d' ' -f1)
    lock=$work/source.lock
    jq -n --arg tag "$tag" --arg commit "$commit" --arg archiveSha256 "$archive_sha" \
        '{tag:$tag,commit:$commit,archiveSha256:$archiveSha256}' > "$lock"
fi

jq -e '
  type == "object"
  and (.tag | type == "string" and test("^[0-9]{8}\\.[0-9]{2}$"))
  and (.commit | type == "string" and test("^[0-9a-f]{40}$"))
  and (.archiveSha256 | type == "string" and test("^[0-9a-f]{64}$"))
' "$lock" >/dev/null || {
    echo 'Invalid upstream source.lock' >&2
    exit 1
}

if [[ $mode == --locked ]]; then
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --retry-delay 1 \
        "https://codeload.github.com/GoogleCloudPlatform/osconfig/tar.gz/$(jq -er .commit "$lock")" \
        -o "$output/source.tar.gz"
fi
expected=$(jq -er .archiveSha256 "$lock")
actual=$(sha256sum "$output/source.tar.gz" | cut -d' ' -f1)
[[ $actual == "$expected" ]] || {
    echo 'Pinned upstream source archive checksum mismatch' >&2
    exit 1
}
cp -- "$lock" "$output/source.lock"
mkdir "$output/upstream"
tar -xzf "$output/source.tar.gz" --strip-components=1 -C "$output/upstream"
chmod -R u+rwX,go-rwx "$output"
printf 'tag=%s\ncommit=%s\narchive_sha256=%s\n' \
    "$(jq -er .tag "$lock")" "$(jq -er .commit "$lock")" "$expected"
