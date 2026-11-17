# Third-party notices

Xe-AntiShell-Central's own source is licensed under the [MIT License](LICENSE).
Third-party components retain their upstream licenses and copyrights. The MIT
license for this repository does not replace those terms.

Distribute this file and the complete [`third_party/licenses/`](third_party/licenses/)
directory with source distributions and compiled binaries. The license texts in
that directory are unmodified upstream texts; the additional notices identified
below are extracted verbatim from upstream source comments.

## Reviewed build and update scope

This central distribution builds only `sentinel-central`, with Go **1.22.0**,
`GOOS=linux`, `GOARCH=amd64`, and `CGO_ENABLED=0` as the original reviewed baseline.
It preserves all 39 upstream license and notice texts inherited from the combined
Xe-AntiShell distribution as a conservative superset. In particular the YAML and
external x/crypto modules listed below were agent dependencies and are absent
from this central module's dependency graph. Including their notices does not
add those modules as dependencies or assert that they are linked here.

The central module pins the MIT-licensed
`github.com/mkjang2000/Xe-AntiShell/protocol v0.1.1` shared contract module from
[Xe-AntiShell](https://github.com/mkjang2000/Xe-AntiShell/tree/protocol/v0.1.1/protocol).
Its project copyright and permission notice is retained in this distribution's
identical [MIT license](LICENSE). The remaining selected packages may be reduced
by compiler dead-code elimination.

The inventory was checked with:

```sh
CGO_ENABLED=0 go list -deps -f '{{if .Module}}{{.Module.Path}}@{{.Module.Version}} {{.ImportPath}}{{end}}' ./cmd/sentinel-central
go version -m build/sentinel-central
```

Refresh this inventory and the copied texts when changing dependencies, the Go
toolchain (including CI's moving `stable` version), target OS/architecture, build
tags, CGO settings, or included commands. A source release does not vendor the
Go module cache, dependency tests, generators, or upstream development tools.

## Go modules

Versions and notices were taken from the corresponding downloaded module source.
The active central dependency versions and content hashes are pinned in
`go.mod`/`go.sum`; this inherited inventory also retains the agent-only rows
identified above. The links identify upstream source at the reviewed version.
`AND` means both licenses apply to different portions; it does not indicate a
choice between licenses.

| Module | Pinned version | License / included notices | Upstream source |
| --- | --- | --- | --- |
| `go.yaml.in/yaml/v3` | `v3.0.5` | `MIT AND Apache-2.0`; [LICENSE](third_party/licenses/go-yaml-v3-LICENSE.txt), [NOTICE](third_party/licenses/go-yaml-v3-NOTICE.txt), [full Apache 2.0 text](third_party/licenses/Apache-2.0.txt) | [yaml/go-yaml](https://github.com/yaml/go-yaml/tree/v3.0.5) |
| `golang.org/x/crypto` | `v0.23.0` | `BSD-3-Clause`; [LICENSE](third_party/licenses/golang-x-crypto-LICENSE.txt), [PATENTS](third_party/licenses/golang-x-crypto-PATENTS.txt) | [golang/crypto](https://github.com/golang/crypto/tree/v0.23.0) |
| `golang.org/x/sys` | `v0.30.0` | `BSD-3-Clause`; [LICENSE](third_party/licenses/golang-x-sys-LICENSE.txt), [PATENTS](third_party/licenses/golang-x-sys-PATENTS.txt) | [golang/sys](https://github.com/golang/sys/tree/v0.30.0) |
| `modernc.org/sqlite` | `v1.36.0` | `BSD-3-Clause`; [LICENSE](third_party/licenses/modernc-sqlite-LICENSE.txt); includes SQLite 3.49.0, discussed below | [modernc/sqlite](https://gitlab.com/cznic/sqlite/-/tree/v1.36.0) |
| `github.com/dustin/go-humanize` | `v1.0.1` | `MIT`; [LICENSE](third_party/licenses/go-humanize-LICENSE.txt) | [dustin/go-humanize](https://github.com/dustin/go-humanize/tree/v1.0.1) |
| `github.com/google/uuid` | `v1.6.0` | `BSD-3-Clause`; [LICENSE](third_party/licenses/google-uuid-LICENSE.txt) | [google/uuid](https://github.com/google/uuid/tree/v1.6.0) |
| `github.com/remyoudompheng/bigfft` | `v0.0.0-20230129092748-24d4a6f8daec` | `BSD-3-Clause`; [LICENSE](third_party/licenses/bigfft-LICENSE.txt) | [remyoudompheng/bigfft](https://github.com/remyoudompheng/bigfft/tree/24d4a6f8daec) |
| `golang.org/x/exp` | `v0.0.0-20230315142452-642cacee5cc0` | `BSD-3-Clause`; [LICENSE](third_party/licenses/golang-x-exp-LICENSE.txt), [PATENTS](third_party/licenses/golang-x-exp-PATENTS.txt) | [golang/exp](https://github.com/golang/exp/tree/642cacee5cc0) |
| `modernc.org/libc` | `v1.61.13` | `BSD-3-Clause` plus bundled notices below; [LICENSE](third_party/licenses/modernc-libc-LICENSE.txt), [LICENSE-GO](third_party/licenses/modernc-libc-LICENSE-GO.txt) | [modernc/libc](https://gitlab.com/cznic/libc/-/tree/v1.61.13) |
| `modernc.org/mathutil` | `v1.7.1` | `BSD-3-Clause`; [LICENSE](third_party/licenses/modernc-mathutil-LICENSE.txt) | [modernc/mathutil](https://gitlab.com/cznic/mathutil/-/tree/v1.7.1) |
| `modernc.org/memory` | `v1.8.2` | `BSD-3-Clause`; [LICENSE](third_party/licenses/modernc-memory-LICENSE.txt), [LICENSE-GO](third_party/licenses/modernc-memory-LICENSE-GO.txt), [LICENSE-MMAP-GO](third_party/licenses/modernc-memory-LICENSE-MMAP-GO.txt) | [modernc/memory](https://gitlab.com/cznic/memory/-/tree/v1.8.2) |

These additional indirect modules are pinned in `go.mod`, but their packages
were not selected by the original reviewed Linux/amd64 build. Their notices are
included for completeness when distributing the project dependency manifest:

| Module | Pinned version | License | Upstream source |
| --- | --- | --- | --- |
| `github.com/mattn/go-isatty` | `v0.0.20` | `MIT`; [LICENSE](third_party/licenses/go-isatty-LICENSE.txt) | [mattn/go-isatty](https://github.com/mattn/go-isatty/tree/v0.0.20) |
| `github.com/ncruces/go-strftime` | `v0.1.9` | `MIT`; [LICENSE](third_party/licenses/go-strftime-LICENSE.txt) | [ncruces/go-strftime](https://github.com/ncruces/go-strftime/tree/v0.1.9) |

### Bundled code in modernc modules

- `modernc.org/libc` includes musl-derived code. Its upstream
  [COPYRIGHT-MUSL](third_party/licenses/modernc-libc-COPYRIGHT-MUSL.txt)
  contains the MIT license, author list, and notices identifying additional
  permissively licensed portions. Preserve the entire file.
- `modernc.org/libc/int128.go` incorporates Luke Champine's uint128 code under
  MIT; its [complete embedded license](third_party/licenses/modernc-libc-uint128-LICENSE.txt)
  is included separately.
- `modernc.org/libc/ccgo_linux_amd64.go` contains a Poul-Henning Kamp
  BSD-2-Clause notice; the [complete embedded notice](third_party/licenses/modernc-libc-crypt-BSD-2-Clause.txt)
  is included conservatively even when the linker removes that routine.
- The translated SQLite engine in `modernc.org/sqlite/lib` is SQLite **3.49.0**.
  SQLite's authors dedicate SQLite to the public domain, separately from the
  BSD-3-Clause Go wrapper. The [upstream blessing](third_party/licenses/sqlite-PUBLIC-DOMAIN.txt)
  is retained. See the [SQLite copyright statement](https://sqlite.org/copyright.html).
- Dependency source comments include API documentation under
  `Linux-man-pages-copyleft`. Those comments are not compiled into the executables;
  this project does not redistribute that dependency's source documentation.
  Preserve those upstream comment notices if additionally vendoring that source.

## Go runtime and standard library

The executable includes the Go runtime and standard-library code. The reviewed
Go 1.22.0 distribution's [BSD-3-Clause LICENSE](third_party/licenses/go-LICENSE.txt)
and [PATENTS](third_party/licenses/go-PATENTS.txt) are included. Source:
[golang/go at go1.22.0](https://github.com/golang/go/tree/go1.22.0).
The standard library also uses vendored `golang.org/x` code covered by the same
Go Authors BSD-3-Clause license; the runtime vendor notices are retained in
`third_party/licenses/go-stdlib-vendor-*-{LICENSE,PATENTS}.txt`.
Additional upstream source notices are preserved for:

- The amd64 runtime's Inferno-derived memory move implementation: [MIT notice](third_party/licenses/go-runtime-memmove-MIT.txt).
- The Ed25519 scalar implementation generated from fiat-crypto v0.0.9:
  [BSD-1-Clause notice](third_party/licenses/go-edwards25519-fiat-BSD-1-Clause.txt).
- SunPro-derived math routines: [SunPro notices](third_party/licenses/go-math-SunPro.txt).
- Cephes-derived math source: [upstream Cephes notice](third_party/licenses/go-math-Cephes.txt).
  This last notice is preserved conservatively from the selected `math` package;
  Cephes routines were absent from the original reviewed unstripped agent's symbol table.

Build-tool-only packages and the optional BoringCrypto distribution are not part
of this reviewed `CGO_ENABLED=0` build.

## External programs: Tetragon and tetra

Tetragon and its `tetra` CLI are separately installed external programs.
The separate Xe-AntiShell agent invokes `tetra` as a subprocess and reads its
JSON output. Central does not invoke, link or redistribute Tetragon, `tetra`,
or their eBPF object files. These inherited external-program notes describe the
agent boundary only; their licenses are not part of the linked central inventory.

Upstream Tetragon's [top-level license](https://github.com/cilium/tetragon/blob/main/LICENSE)
is Apache-2.0, while its [README](https://github.com/cilium/tetragon/blob/main/README.md)
also identifies BSD/GPL components. For example, the
[execve eBPF source](https://github.com/cilium/tetragon/blob/main/bpf/process/bpf_execve_event.c)
declares `GPL-2.0-only OR BSD-2-Clause`; this file's declaration does not establish
the license of every upstream eBPF file. Use the license files, source headers,
third-party notices, and distribution obligations for the exact separately
installed upstream release. If a future package bundles these external
artifacts, prepare their release-specific notices before distributing it.
