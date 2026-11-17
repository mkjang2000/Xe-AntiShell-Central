#!/usr/bin/env bash
# Verify central installation orchestration without changing host packages/state.
set -euo pipefail
test_source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$test_source_root/install.sh"
test_work=$(mktemp -d)
trap 'rm -rf -- "$test_work"' EXIT
test_calls=$test_work/calls
test_package=xe-antishell-central
test_candidate='xe-antishell-central-(none):0.1.0-1.el9.x86_64'
test_installed=''
test_owner=''
test_install_failure=false
test_active=true
test_build_count=1
XEAS_CENTRAL_STATE_FILE=$test_work/state/state.json
XEAS_CENTRAL_BINARY=$test_work/sentinel-central
test_rpm=$test_work/package.rpm
mkdir "$test_work/state"
printf 'local package fixture\n' > "$test_rpm"
: > "$test_calls"

require_root() { :; }
require_command() { :; }
sleep() { :; }
rpm() {
  printf 'rpm' >> "$test_calls"; printf ' <%s>' "$@" >> "$test_calls"; printf '\n' >> "$test_calls"
  case "$1" in
    -qp)
      if [[ "$3" == '%{NAME}' ]]; then printf '%s' "$test_package"; else printf '%s' "$test_candidate"; fi ;;
    -q) [[ -n "$test_installed" ]] && printf '%s' "$test_installed" ;;
    -qf) [[ -n "$test_owner" ]] && printf '%s' "$test_owner" ;;
    -Uvh) [[ "$test_install_failure" == false ]] ;;
    *) return 1 ;;
  esac
}
systemctl() {
  printf 'systemctl' >> "$test_calls"; printf ' <%s>' "$@" >> "$test_calls"; printf '\n' >> "$test_calls"
  case "$1" in
    show) printf 'Version=252\n' ;;
    daemon-reload) : ;;
    enable) [[ "$*" == 'enable --now sentinel-central.service' ]] ;;
    is-active) [[ "$*" == 'is-active --quiet sentinel-central.service' && "$test_active" == true ]] ;;
    *) return 1 ;;
  esac
}
build_local_rpm() {
  local n
  printf 'source-build\n' >> "$test_calls"
  for (( n=0; n<test_build_count; n++ )); do printf 'build fixture\n' > "$1/central-$n.rpm"; done
}
expect_failure() {
  if main "$@" > "$test_work/stdout" 2> "$test_work/stderr"; then
    printf 'Expected installer failure: %s\n' "$*" >&2; exit 1
  fi
}
assert_no_install() {
  ! grep -Eq 'rpm <-Uvh>|systemctl <enable>' "$test_calls" || { printf 'Invalid input installed or started a service.\n' >&2; exit 1; }
}
assert_central_only() {
  if grep -Eq 'sentineld|sentinel-web|managed|firewall|init>|chown|chmod' "$test_calls"; then
    printf 'Installer crossed central package/state boundaries.\n' >&2; exit 1
  fi
}

main --help > "$test_work/help"
expect_failure
expect_failure --unknown
expect_failure --rpm
expect_failure --build --rpm "$test_rpm"
expect_failure --rpm "$test_work/missing.rpm"
assert_no_install

# A new package install never initializes PKI/DB or starts the service.
: > "$test_calls"
main --rpm "$test_rpm" > "$test_work/stdout"
grep -q 'rpm <-Uvh>' "$test_calls"
! grep -q 'systemctl <enable>' "$test_calls"
grep -q 'without initialization' "$test_work/stdout"
assert_central_only

# Existing state bytes and permissions survive an upgrade and same-version run.
printf 'EXISTING_STATE_FIXTURE\n' > "$XEAS_CENTRAL_STATE_FILE"
chmod 0600 "$XEAS_CENTRAL_STATE_FILE"
cp "$XEAS_CENTRAL_STATE_FILE" "$test_work/state-before"
: > "$test_calls"
main --rpm "$test_rpm" > "$test_work/stdout"
cmp "$test_work/state-before" "$XEAS_CENTRAL_STATE_FILE"
[[ $(stat -c '%a' "$XEAS_CENTRAL_STATE_FILE") == 600 ]]
grep -q 'systemctl <enable> <--now> <sentinel-central.service>' "$test_calls"
assert_central_only
test_installed=$test_candidate
: > "$test_calls"
main --rpm "$test_rpm" > "$test_work/stdout"
! grep -q 'rpm <-Uvh>' "$test_calls"
cmp "$test_work/state-before" "$XEAS_CENTRAL_STATE_FILE"
test_installed=''

# Legacy ownership is resolved explicitly before any package or service mutation.
printf 'legacy binary fixture\n' > "$XEAS_CENTRAL_BINARY"
test_owner=xe-antishell
: > "$test_calls"
expect_failure --rpm "$test_rpm"
assert_no_install
grep -q 'migrate RPM ownership' "$test_work/stderr"
test_owner=xe-antishell-central

# Wrong packages, symlink state and package failures cannot start the service.
test_package=unrelated-package
: > "$test_calls"
expect_failure --rpm "$test_rpm"
assert_no_install
test_package=xe-antishell-central
mv "$XEAS_CENTRAL_STATE_FILE" "$test_work/real-state"
ln -s "$test_work/real-state" "$XEAS_CENTRAL_STATE_FILE"
: > "$test_calls"
expect_failure --rpm "$test_rpm"
assert_no_install
rm "$XEAS_CENTRAL_STATE_FILE"
mv "$test_work/real-state" "$XEAS_CENTRAL_STATE_FILE"
test_install_failure=true
: > "$test_calls"
expect_failure --rpm "$test_rpm"
! grep -q 'systemctl <enable>' "$test_calls"
test_install_failure=false
test_active=false
: > "$test_calls"
expect_failure --rpm "$test_rpm"
test_active=true

# Source builds must produce one RPM and reuse exactly the same setup path.
: > "$test_calls"
main --build > "$test_work/stdout"
grep -q '^source-build$' "$test_calls"
assert_central_only
for test_build_count in 0 2; do
  : > "$test_calls"
  expect_failure --build
  assert_no_install
done
printf 'Central installer command-mock checks passed; no host mutation occurred.\n'
