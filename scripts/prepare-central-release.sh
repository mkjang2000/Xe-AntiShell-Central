#!/usr/bin/env bash
# Sign the two CI-built Central RPMs. The output directory contains only public assets.
set -euo pipefail
if [[ $# != 4 ]]; then
  printf 'Usage: %s TAG ACTIONS_ARTIFACT_DIR PUBLISHER_KEY NEW_OUTPUT_DIR\n' "$0" >&2
  exit 2
fi
tag=$1
candidates=$(realpath -e -- "$2")
key=$(realpath -e -- "$3")
output=$(realpath -m -- "$4")
[[ "$tag" =~ ^v([0-9]+[.][0-9]+[.][0-9]+)-r([1-9][0-9]*)$ ]] || { echo 'Invalid release tag' >&2; exit 2; }
version=${BASH_REMATCH[1]}
release=${BASH_REMATCH[2]}
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
commit=$(git rev-parse --verify --end-of-options "refs/tags/$tag^{commit}")
[[ "$(git rev-parse HEAD)" == "$commit" ]] || { echo 'Check out the release tag first' >&2; exit 1; }
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
go build -trimpath -o "$work/xeas-central-release" ./cmd/xeas-central-release
mkdir "$work/public"
for major in 9 10; do
  src="$candidates/unsigned-central-el$major-amd64"
  name="xe-antishell-central-$version-$release.el$major.x86_64.rpm"
  [[ -f "$src/$name" && ! -L "$src/$name" && "$(< "$src/source-commit.txt")" == "$commit" ]] || { echo "Unexpected EL$major candidate" >&2; exit 1; }
  cp -- "$src/$name" "$work/public/$name"
  "$work/xeas-central-release" sign --rpm "$work/public/$name" --tag "$tag" --key "$key" --out "$work/public/$name.manifest.json"
  "$work/xeas-central-release" verify --rpm "$work/public/$name" --manifest "$work/public/$name.manifest.json"
done
el9=$(sha256sum < "$work/public/xe-antishell-central-$version-$release.el9.x86_64.rpm")
el10=$(sha256sum < "$work/public/xe-antishell-central-$version-$release.el10.x86_64.rpm")
sed -e "s/@CENTRAL_TAG@/$tag/g" -e "s/@CENTRAL_EL9_SHA256@/${el9%% *}/g" -e "s/@CENTRAL_EL10_SHA256@/${el10%% *}/g" \
  packaging/bootstrap-central.sh.in > "$work/public/bootstrap-central.sh"
(cd "$work/public" && sha256sum -- *.rpm *.rpm.manifest.json bootstrap-central.sh > SHA256SUMS)
mkdir -- "$output"
cp -- "$work/public/"* "$output/"
printf 'Verified public assets in %s\n' "$output"
