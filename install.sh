#!/usr/bin/env bash
# Install the central package without creating or replacing runtime state.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin

XEAS_CENTRAL_INSTALL_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
XEAS_CENTRAL_BUILD_SCRIPT=$XEAS_CENTRAL_INSTALL_ROOT/scripts/build-rpm.sh
XEAS_CENTRAL_STATE_FILE=/var/lib/xe-antishell-central/state.json
XEAS_CENTRAL_BINARY=/usr/sbin/sentinel-central

usage() {
  cat <<'USAGE'
Usage: sudo ./install.sh (--rpm PATH | --build)

  --rpm PATH  Install a supplied local xe-antishell-central RPM
  --build     Build this checkout with scripts/build-rpm.sh, then install
  -h, --help  Show this help

Dependencies must already be installed. Existing keys, DB, state and systemd
overrides are preserved. This installer never initializes central or changes
firewall rules. It starts only central, and only when existing state.json is
present. A new installation requires a separate explicit sentinel-central init.
A legacy combined agent RPM needs a separately coordinated ownership migration.
USAGE
}

fail() { printf 'install.sh: %s\n' "$*" >&2; return 1; }
require_root() { (( EUID == 0 )) || fail 'Run this installer as root.'; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "Required command is missing: $1"; }
check_regular_file() {
  [[ -f "$1" && -r "$1" && ! -L "$1" ]] || fail "Expected a readable regular file, not a symlink: $1"
}
build_local_rpm() { "$XEAS_CENTRAL_BUILD_SCRIPT" --output-dir "$1"; }

check_central_active() {
  # Type=simple may become active briefly before listener or key loading fails.
  systemctl is-active --quiet sentinel-central.service || return 1
  sleep 1
  systemctl is-active --quiet sentinel-central.service
}

check_existing_state() {
  local directory=${XEAS_CENTRAL_STATE_FILE%/*}
  [[ ! -L "$directory" ]] || { fail 'The central state directory must not be a symlink.'; return 1; }
  if [[ -e "$XEAS_CENTRAL_STATE_FILE" || -L "$XEAS_CENTRAL_STATE_FILE" ]]; then
    check_regular_file "$XEAS_CENTRAL_STATE_FILE" || return 1
  fi
}

check_legacy_owner() {
  local owner
  if [[ -e "$XEAS_CENTRAL_BINARY" || -L "$XEAS_CENTRAL_BINARY" ]]; then
    owner=$(rpm -qf --queryformat '%{NAME}' -- "$XEAS_CENTRAL_BINARY" 2>/dev/null) || owner=''
    if [[ "$owner" == xe-antishell ]]; then
      fail 'The combined xe-antishell RPM owns central. Preserve state and migrate RPM ownership before running this installer.'
      return 1
    fi
  fi
}

main() (
  local rpm_path='' with_build=false option value build_directory=''
  local package_name candidate_nevra installed_nevra manager_version
  local nevra_format='%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}'
  trap '[[ -z "$build_directory" ]] || rm -rf -- "$build_directory"' EXIT
  while (( $# )); do
    option=$1
    case "$option" in
      -h|--help) usage; return 0 ;;
      --build) with_build=true; shift ;;
      --rpm)
        (( $# >= 2 )) && [[ -n "$2" && "$2" != --* ]] || { fail 'Missing value for --rpm.'; return 1; }
        rpm_path=$2; shift 2 ;;
      *) fail "Unknown option: $option"; return 1 ;;
    esac
  done
  if [[ "$with_build" == true && -n "$rpm_path" ]] || [[ "$with_build" == false && -z "$rpm_path" ]]; then
    fail 'Choose exactly one of --rpm PATH or --build.'; return 1
  fi
  require_root || return 1
  umask 077
  for value in rpm systemctl; do require_command "$value" || return 1; done
  if [[ "$with_build" == true ]]; then
    for value in mktemp rm; do require_command "$value" || return 1; done
    check_regular_file "$XEAS_CENTRAL_BUILD_SCRIPT" || return 1
    [[ -x "$XEAS_CENTRAL_BUILD_SCRIPT" ]] || { fail 'The RPM build helper must be executable.'; return 1; }
  else
    check_regular_file "$rpm_path" || return 1
  fi
  check_existing_state || return 1
  check_legacy_owner || return 1
  manager_version=$(systemctl show --property=Version --no-pager) || {
    fail 'A running systemd system manager is required for installation.'; return 1
  }
  [[ "$manager_version" =~ ^Version=[0-9]+ ]] || { fail 'Cannot identify the running systemd manager.'; return 1; }
  if [[ "$with_build" == true ]]; then
    build_directory=$(mktemp -d /tmp/xeas-central-install.XXXXXX) || return 1
    build_local_rpm "$build_directory" || return 1
    shopt -s nullglob
    local artifacts=("$build_directory"/*.rpm)
    (( ${#artifacts[@]} == 1 )) || { fail 'The build helper must produce exactly one RPM.'; return 1; }
    rpm_path=${artifacts[0]}
    check_regular_file "$rpm_path" || return 1
  fi
  package_name=$(rpm -qp --queryformat '%{NAME}' -- "$rpm_path") || return 1
  [[ "$package_name" == xe-antishell-central ]] || { fail 'The supplied RPM is not xe-antishell-central.'; return 1; }
  candidate_nevra=$(rpm -qp --queryformat "$nevra_format" -- "$rpm_path") || return 1
  installed_nevra=$(rpm -q --queryformat "$nevra_format" xe-antishell-central 2>/dev/null) || installed_nevra=''
  if [[ "$installed_nevra" == "$candidate_nevra" ]]; then
    printf 'The same central RPM version and architecture are installed; preserving state.\n'
  else
    rpm -Uvh -- "$rpm_path" || return 1
  fi
  systemctl daemon-reload || return 1
  check_existing_state || return 1
  if [[ -f "$XEAS_CENTRAL_STATE_FILE" ]]; then
    systemctl enable --now sentinel-central.service || return 1
    check_central_active || {
      fail 'Central is not active. Check journalctl -u sentinel-central.service.'; return 1
    }
    printf 'Central installed and started with the existing state directory.\n'
  else
    printf 'Central installed without initialization. For a new server, run explicitly:\n'
    printf '  sentinel-central init --state-dir /var/lib/xe-antishell-central --hosts localhost,127.0.0.1,::1\n'
    printf '  systemctl enable --now sentinel-central.service\n'
  fi
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
