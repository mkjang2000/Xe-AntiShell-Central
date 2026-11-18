#!/usr/bin/env bash
# Build a local RPM from a reviewed checkout without installing host packages.
set -euo pipefail
PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
XEAS_BUILD_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

build_usage() {
  cat <<'USAGE'
Usage: scripts/build-rpm.sh [--output-dir DIR] [--force]

Build one xe-antishell-central RPM from this source tree. Output defaults to dist/rpm.
--force allows replacing the same output RPM name; other files are preserved.

Requires Linux, Bash, Go 1.22+, rpm/rpmbuild, systemd RPM macros, make, GNU tar,
Python 3.9+ and Git. Go uses this installed toolchain and pinned go.mod/go.sum.
Go module downloads may be needed when the module cache is empty.
No package installation, service restart, firewall or enforcement change occurs.
USAGE
}

build_fail() { printf 'build-rpm.sh: %s\n' "$*" >&2; return 1; }
build_find_tool() {
  local path
  path=$(type -P "$1") || { build_fail "Required build tool is missing: $1"; return 1; }
  printf '%s\n' "$path"
}

build_check_dependencies() {
  local version_output compiler major minor
  XEAS_GO_TOOL=$(build_find_tool go) || return 1
  XEAS_RPM_TOOL=$(build_find_tool rpm) || return 1
  XEAS_RPMBUILD_TOOL=$(build_find_tool rpmbuild) || return 1
  XEAS_MAKE_TOOL=$(build_find_tool make) || return 1
  XEAS_TAR_TOOL=$(build_find_tool tar) || return 1
  XEAS_PYTHON_TOOL=$(build_find_tool python3) || return 1
  XEAS_GIT_TOOL=$(build_find_tool git) || return 1
  "$XEAS_PYTHON_TOOL" -c 'import sys; sys.exit(sys.version_info < (3, 9))' || {
    build_fail 'Python 3.9 or newer is required for source checks.'; return 1
  }
  version_output=$(GOTOOLCHAIN=local "$XEAS_GO_TOOL" version) || return 1
  read -r _ _ compiler _ <<< "$version_output"
  if [[ ! "$compiler" =~ ^go([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]]; then
    build_fail 'Use a stable installed Go toolchain, version 1.22 or newer.'; return 1
  fi
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}
  if (( major < 1 || (major == 1 && minor < 22) )); then
    build_fail 'Go 1.22 or newer is required.'; return 1
  fi
  XEAS_GO_VERSION=$compiler
  [[ $("$XEAS_TAR_TOOL" --version) == *'GNU tar'* ]] || { build_fail 'GNU tar is required.'; return 1; }
  [[ $("$XEAS_RPM_TOOL" --eval '%{?systemd_post:available}') == available ]] || {
    build_fail 'Install the systemd RPM macro package before building.'; return 1
  }
}

# Keep private deployment files out even when they are ignored by Git. Only
# maintained code formats and explicitly selected package/config/docs enter tar.
build_source_paths() (
  cd -- "$XEAS_BUILD_ROOT" || return 1
  local path source_dir
  local required=(go.mod go.sum Makefile install.sh README.md Project_tree.md
    LICENSE THIRD_PARTY_NOTICES.md
    packaging/rpm/xe-antishell-central.spec
    packaging/systemd/sentinel-central.service packaging/systemd/sentinel-central-updater.socket packaging/systemd/sentinel-central-updater.service packaging/install_test.sh)
  for path in "${required[@]}"; do
    [[ -f "$path" && ! -L "$path" ]] || { build_fail "Required source file is missing or a symlink: $path"; return 1; }
    printf '%s\0' "$path"
  done
  [[ -d third_party/licenses && ! -L third_party/licenses ]] || {
    build_fail 'The upstream license directory is required.'; return 1
  }
  [[ -n $(find third_party/licenses -type f \( -name '*.txt' -o -name '*.md' \) -print -quit) ]] || {
    build_fail 'The upstream license directory must contain license texts.'; return 1
  }
  for path in .gitignore .gitattributes .release-files .releaseignore LICENSE.md COPYING NOTICE CHANGELOG.md CONTRIBUTING.md SECURITY.md devdocs/analysis/managed-v1-operations.md; do
    [[ ! -L "$path" ]] || { build_fail "Source symlink is not allowed: $path"; return 1; }
    [[ ! -f "$path" ]] || printf '%s\0' "$path"
  done
  for source_dir in cmd/sentinel-central cmd/xeas-central-release internal/central internal/selfupdate internal/githubrelease internal/console scripts devdocs/plans devdocs/reviews .github/workflows third_party/licenses; do
    [[ ! -L "$source_dir" ]] || { build_fail "Source directory symlink is not allowed: $source_dir"; return 1; }
    [[ -d "$source_dir" ]] || continue
    if [[ -n $(find "$source_dir" -type l -print -quit) ]]; then
      build_fail "Source symlinks are not allowed under $source_dir"; return 1
    fi
    case "$source_dir" in
      cmd/sentinel-central|cmd/xeas-central-release|internal/central|internal/selfupdate|internal/githubrelease) find "$source_dir" -path '*/.*' -prune -o -type f \( -name '*.go' -o -name '*.sql' \) -print0 ;;
      internal/console) find "$source_dir" -path '*/.*' -prune -o -type f \( -name '*.go' -o -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.mjs' \) -print0 ;;
      scripts) find "$source_dir" -path '*/.*' -prune -o -type f \( -name '*.sh' -o -name '*.py' \) -print0 ;;
      .github/workflows) find "$source_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 ;;
      devdocs/*) find "$source_dir" -type f -name '*.md' -print0 ;;
      third_party/licenses) find "$source_dir" -type f \( -name '*.txt' -o -name '*.md' \) -print0 ;;
    esac || return 1
  done
)

build_main() (
  local output_dir="$XEAS_BUILD_ROOT/dist/rpm" force=false option build_work source_name package_version package_name rpm_path destination temporary=''
  local -a packages=()
  while (( $# )); do
    option=$1
    case "$option" in
      -h|--help) build_usage; return 0 ;;
      --force) force=true; shift ;;
      --output-dir)
        (( $# >= 2 )) && [[ -n "$2" && "$2" != --* ]] || { build_fail 'Missing value for --output-dir.'; return 1; }
        output_dir=$2; shift 2 ;;
      *) build_fail "Unknown build option: $option"; return 1 ;;
    esac
  done
  [[ ! -L "$output_dir" ]] || { build_fail 'The output directory must not be a symlink.'; return 1; }
  [[ ! -e "$output_dir" || -d "$output_dir" ]] || { build_fail 'The output path is not a directory.'; return 1; }
  build_check_dependencies || return 1
  GOTOOLCHAIN=local "$XEAS_MAKE_TOOL" -C "$XEAS_BUILD_ROOT" check-source || return 1
  package_name=$(awk '$1=="Name:" {print $2; exit}' "$XEAS_BUILD_ROOT/packaging/rpm/xe-antishell-central.spec")
  package_version=$(awk '$1=="Version:" {print $2; exit}' "$XEAS_BUILD_ROOT/packaging/rpm/xe-antishell-central.spec")
  [[ "$package_name" == xe-antishell-central && "$package_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    build_fail 'Unsupported package name or version in the RPM spec.'; return 1
  }
  umask 077
  build_work=$(mktemp -d "${TMPDIR:-/tmp}/xeas-central-rpm-build.XXXXXX") || return 1
  trap 'rm -rf -- "$build_work"; [[ -z "$temporary" ]] || rm -f -- "$temporary"' EXIT
  mkdir -p -- "$build_work/BUILD" "$build_work/BUILDROOT" "$build_work/RPMS" "$build_work/SOURCES" "$build_work/SRPMS" "$build_work/tmp" || return 1
  build_source_paths > "$build_work/paths" || return 1
  LC_ALL=C sort -zu "$build_work/paths" > "$build_work/sorted-paths" || return 1
  # Evaluate the checkout's ignore rules without requiring a first commit or
  # changing its Git metadata. This also works in an unpacked source archive.
  "$XEAS_GIT_TOOL" init --bare --quiet "$build_work/ignore.git" || return 1
  local ignore_status=0
  "$XEAS_GIT_TOOL" -c core.bare=false -c core.excludesFile=/dev/null \
    --git-dir "$build_work/ignore.git" --work-tree "$XEAS_BUILD_ROOT" \
    check-ignore --no-index --stdin -z < "$build_work/sorted-paths" > "$build_work/ignored-paths" || ignore_status=$?
  (( ignore_status <= 1 )) || return 1
  "$XEAS_PYTHON_TOOL" -c 'import pathlib,sys; paths=pathlib.Path(sys.argv[1]).read_bytes().split(b"\0"); ignored=set(pathlib.Path(sys.argv[2]).read_bytes().split(b"\0")); sys.stdout.buffer.write(b"".join(path+b"\0" for path in paths if path and path not in ignored))' \
    "$build_work/sorted-paths" "$build_work/ignored-paths" > "$build_work/public-paths" || return 1
  source_name="$package_name-$package_version"
  "$XEAS_TAR_TOOL" -C "$XEAS_BUILD_ROOT" --null --verbatim-files-from --no-recursion \
    --transform "s,^,$source_name/," -czf "$build_work/SOURCES/$source_name.tar.gz" \
    -T "$build_work/public-paths" || return 1
  printf 'Building with %s. RPM database build-dependency checks are skipped after tool/macro preflight.\n' "$XEAS_GO_VERSION"
  # The SDK may be manually installed rather than registered as an RPM.
  # --nodeps affects this build only; the installer still checks runtime deps.
  GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 "$XEAS_RPMBUILD_TOOL" -bb --nodeps \
    --define "_topdir $build_work" --define "_tmppath $build_work/tmp" \
    "$XEAS_BUILD_ROOT/packaging/rpm/xe-antishell-central.spec" || return 1
  while IFS= read -r -d '' rpm_path; do packages+=("$rpm_path"); done < <(find "$build_work/RPMS" -type f -name 'xe-antishell-central-*.rpm' -print0)
  (( ${#packages[@]} == 1 )) || { build_fail 'Expected exactly one built central RPM.'; return 1; }
  mkdir -p -- "$output_dir" || return 1
  [[ ! -L "$output_dir" && -d "$output_dir" ]] || { build_fail 'The output directory changed during build.'; return 1; }
  output_dir=$(cd -- "$output_dir" && pwd -P) || return 1
  destination="$output_dir/${packages[0]##*/}"
  [[ ! -L "$destination" ]] || { build_fail 'Refusing to replace a symlink at the output RPM path.'; return 1; }
  if [[ -e "$destination" && "$force" != true ]]; then
    build_fail 'The output RPM already exists. Choose another directory or use --force.'; return 1
  fi
  [[ ! -e "$destination" || -f "$destination" ]] || { build_fail 'The output RPM path is not a regular file.'; return 1; }
  temporary=$(mktemp "$output_dir/.xeas-rpm.XXXXXX") || return 1
  cp -- "${packages[0]}" "$temporary" || return 1
  chmod 0644 "$temporary" || return 1
  if [[ "$force" == true ]]; then
    mv -f -T -- "$temporary" "$destination" || return 1
  else
    # The same-filesystem hard link publishes only complete bytes and fails if
    # another build created the destination after the preflight check.
    ln -T -- "$temporary" "$destination" || return 1
    rm -f -- "$temporary" || return 1
  fi
  printf 'Built RPM: %s\n' "$destination"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then build_main "$@"; fi
