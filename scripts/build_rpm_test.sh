#!/usr/bin/env bash
# Check the build orchestration with real source archives and mocked compilers.
set -euo pipefail
test_source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$test_source_root/scripts/build-rpm.sh"
test_work=$(mktemp -d)
trap 'rm -rf -- "$test_work"' EXIT
export XEAS_MOCK_WORK=$test_work
export XEAS_MOCK_CALLS=$test_work/calls
export XEAS_MOCK_CAPTURE=$test_work/source.tar.gz
export XEAS_MOCK_GO_VERSION=go1.22.0
export XEAS_MOCK_MACROS=available
export XEAS_MOCK_GUARD=success
export XEAS_MOCK_COUNT=1
export XEAS_MOCK_PAYLOAD=COMPLETE_RPM_FIXTURE
export XEAS_MOCK_PYTHON_OK=true
export XEAS_TEST_PYTHON
XEAS_TEST_PYTHON=$(type -P python3)
test_missing_tool=''
mkdir -p "$test_work/tools" "$test_work/source"
XEAS_BUILD_ROOT=$test_work/source

for test_path in go.mod go.sum Makefile install.sh README.md Project_tree.md \
  LICENSE THIRD_PARTY_NOTICES.md third_party/licenses/upstream-LICENSE.txt \
  packaging/rpm/xe-antishell-central.spec \
  packaging/systemd/sentinel-central.service packaging/install_test.sh \
  cmd/sentinel-central/main.go internal/central/store.go \
  scripts/check-source.py scripts/build-rpm.sh \
  devdocs/plans/install.md devdocs/reviews/security.md \
  devdocs/analysis/managed-v1-operations.md; do
  mkdir -p -- "$XEAS_BUILD_ROOT/$(dirname -- "$test_path")"
  printf 'maintained fixture\n' > "$XEAS_BUILD_ROOT/$test_path"
done
printf 'Name: xe-antishell-central\nVersion: 0.1.0\n' > "$XEAS_BUILD_ROOT/packaging/rpm/xe-antishell-central.spec"
printf 'internal/central/private.go\nscripts/private_notes.py\n' > "$XEAS_BUILD_ROOT/.gitignore"
for test_path in .aws/credentials .codex/session.json .git/config .env \
  internal/central/private.go internal/central/site.json internal/central/signing.key internal/central/private.pem \
  internal/central/.private/hidden.go scripts/private_notes.py configs/hosts/real.yaml \
  packaging/systemd/sentinel-central-local-ports.conf devdocs/analysis/private-host.md \
  cmd/sentineld/main.go internal/agent/agent.go build/sentinel-central dist/rpm/old.rpm; do
  mkdir -p -- "$XEAS_BUILD_ROOT/$(dirname -- "$test_path")"
  printf 'DO_NOT_ARCHIVE_PRIVATE_FIXTURE\n' > "$XEAS_BUILD_ROOT/$test_path"
done

cat > "$test_work/tools/go" <<'MOCK'
#!/usr/bin/env bash
[[ "$GOTOOLCHAIN" == local && "$1" == version ]] || exit 1
printf 'go version %s linux/amd64\n' "$XEAS_MOCK_GO_VERSION"
MOCK
cat > "$test_work/tools/rpm" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == --eval ]] || exit 1
printf '%s\n' "$XEAS_MOCK_MACROS"
MOCK
cat > "$test_work/tools/python3" <<'MOCK'
#!/usr/bin/env bash
if [[ "${2:-}" == *sys.version_info* && "$XEAS_MOCK_PYTHON_OK" != true ]]; then exit 1; fi
exec "$XEAS_TEST_PYTHON" "$@"
MOCK
cat > "$test_work/tools/make" <<'MOCK'
#!/usr/bin/env bash
printf 'source-guard\n' >> "$XEAS_MOCK_CALLS"
[[ "$1" == -C && "$3" == check-source && "$XEAS_MOCK_GUARD" == success ]]
MOCK
cat > "$test_work/tools/rpmbuild" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$GOTOOLCHAIN" == local && "$GOWORK" == off && "$CGO_ENABLED" == 0 ]] || exit 1
printf 'rpmbuild\n' >> "$XEAS_MOCK_CALLS"
topdir=''; nodeps=false
while (( $# )); do
  case "$1" in
    --define) [[ "$2" != '_topdir '* ]] || topdir=${2#_topdir }; shift 2 ;;
    --nodeps) nodeps=true; shift ;;
    *) shift ;;
  esac
done
[[ -n "$topdir" && "$nodeps" == true ]]
cp "$topdir/SOURCES/xe-antishell-central-0.1.0.tar.gz" "$XEAS_MOCK_CAPTURE"
mkdir -p "$topdir/RPMS/x86_64"
for (( n=0; n<XEAS_MOCK_COUNT; n++ )); do
  printf '%s\n' "$XEAS_MOCK_PAYLOAD" > "$topdir/RPMS/x86_64/xe-antishell-central-0.1.0-$((n+1)).x86_64.rpm"
done
MOCK
chmod 0755 "$test_work/tools/"*

build_find_tool() {
  [[ "$1" != "$test_missing_tool" ]] || return 1
  case "$1" in
    go|rpm|rpmbuild|make|python3) printf '%s/tools/%s\n' "$test_work" "$1" ;;
    *) type -P "$1" ;;
  esac
}

expect_failure() {
  if build_main "$@" > "$test_work/stdout" 2> "$test_work/stderr"; then
    printf 'Expected build failure: %s\n' "$*" >&2; exit 1
  fi
}
assert_no_build() { [[ ! -s "$XEAS_MOCK_CALLS" ]] || { printf 'Invalid input started a build.\n' >&2; exit 1; }; }
: > "$XEAS_MOCK_CALLS"
build_main --help > "$test_work/help"
expect_failure --unknown; assert_no_build
expect_failure --output-dir; assert_no_build
printf 'not a directory\n' > "$test_work/output-file"
expect_failure --output-dir "$test_work/output-file"; assert_no_build
mkdir "$test_work/real-output"
ln -s "$test_work/real-output" "$test_work/output-link"
expect_failure --output-dir "$test_work/output-link"; assert_no_build
test_missing_tool=go
expect_failure --output-dir "$test_work/not-created"; assert_no_build
[[ ! -e "$test_work/not-created" ]]
test_missing_tool=''
XEAS_MOCK_PYTHON_OK=false
expect_failure --output-dir "$test_work/not-created"; assert_no_build
[[ ! -e "$test_work/not-created" ]]
XEAS_MOCK_PYTHON_OK=true
XEAS_MOCK_GO_VERSION=go1.21.9
expect_failure --output-dir "$test_work/not-created"; assert_no_build
XEAS_MOCK_GO_VERSION=devel
expect_failure --output-dir "$test_work/not-created"; assert_no_build
XEAS_MOCK_GO_VERSION=go1.22.0
XEAS_MOCK_MACROS=missing
expect_failure --output-dir "$test_work/not-created"; assert_no_build
XEAS_MOCK_MACROS=available
XEAS_MOCK_GUARD=fail
expect_failure --output-dir "$test_work/not-created"
[[ $(< "$XEAS_MOCK_CALLS") == source-guard ]]
XEAS_MOCK_GUARD=success

: > "$XEAS_MOCK_CALLS"
output="$test_work/output with spaces"
build_main --output-dir "$output" > "$test_work/stdout" 2> "$test_work/stderr"
artifact="$output/xe-antishell-central-0.1.0-1.x86_64.rpm"
[[ -f "$artifact" && $(< "$artifact") == COMPLETE_RPM_FIXTURE ]]
[[ $(stat -c '%a' "$artifact") == 644 ]]
[[ $(< "$XEAS_MOCK_CALLS") == $'source-guard\nrpmbuild' ]]
python3 - "$XEAS_MOCK_CAPTURE" <<'PY'
import sys,tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    names = set(archive.getnames())
    root = 'xe-antishell-central-0.1.0/'
    for expected in ['README.md','LICENSE','THIRD_PARTY_NOTICES.md','third_party/licenses/upstream-LICENSE.txt','go.mod','cmd/sentinel-central/main.go','internal/central/store.go','devdocs/plans/install.md','devdocs/analysis/managed-v1-operations.md']:
        assert root+expected in names, expected
    for member in archive.getmembers():
        assert member.name.startswith(root)
        assert member.isfile()
        assert b'DO_NOT_ARCHIVE_PRIVATE_FIXTURE' not in archive.extractfile(member).read(), member.name
PY
[[ "$(< "$test_work/stdout")" != *'DO_NOT_ARCHIVE_PRIVATE_FIXTURE'* ]]

# Ordinary repeat builds preserve existing bytes; replacement is explicit.
XEAS_MOCK_PAYLOAD=SECOND_COMPLETE_RPM_FIXTURE
expect_failure --output-dir "$output"
[[ $(< "$artifact") == COMPLETE_RPM_FIXTURE ]]
build_main --output-dir "$output" --force > "$test_work/stdout" 2> "$test_work/stderr"
[[ $(< "$artifact") == SECOND_COMPLETE_RPM_FIXTURE ]]
printf 'preserved unrelated file\n' > "$output/notes.txt"
build_main --output-dir "$output" --force > "$test_work/stdout" 2> "$test_work/stderr"
[[ $(< "$output/notes.txt") == 'preserved unrelated file' ]]
rm "$artifact"
ln -s "$output/notes.txt" "$artifact"
expect_failure --output-dir "$output" --force
[[ $(< "$output/notes.txt") == 'preserved unrelated file' ]]

# Missing/extra artifacts or source symlinks do not publish an output RPM.
XEAS_MOCK_COUNT=0
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
XEAS_MOCK_COUNT=2
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
XEAS_MOCK_COUNT=1
mv "$XEAS_BUILD_ROOT/third_party/licenses/upstream-LICENSE.txt" "$test_work/license-backup"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
mv "$test_work/license-backup" "$XEAS_BUILD_ROOT/third_party/licenses/upstream-LICENSE.txt"
mv "$XEAS_BUILD_ROOT/LICENSE" "$test_work/project-license-backup"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
mv "$test_work/project-license-backup" "$XEAS_BUILD_ROOT/LICENSE"
ln -s "$test_work/output-file" "$XEAS_BUILD_ROOT/internal/central/source-link.go"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]

printf 'RPM build command-mock and source-archive checks passed. No host packages or services were changed.\n'
