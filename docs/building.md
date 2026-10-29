# Building and Testing peios-rs

Use pekit to build peios-rs and run its tests. Pekit builds each crate on
its own, so a change rebuilds only the crates it reaches. The supported
development host is x86-64 Linux.

## Before you start

You need pekit and Git. Everything else is pinned and fetched by pekit on
the first build: the Bootlin C toolchain, Rust 1.98.1, libclang, the
crates `Cargo.lock` selects, and the Peios SDK. The first build needs
network access; later builds find what they need in pekit's store, and
every step runs without network access in a sandbox that holds only its
declared inputs.

`peios-sys` binds libpeios with bindgen and links it. Pekit builds libpeios
and its headers from the Peios SDK's own files, through the SDK's GCSL
library, which `build.gcsl` imports. `pekit lock` pins the SDK's commit,
and the gcslib libraries', in `pekit.lock`. Use libpeios 0.5.12 or later:
its event reader keeps a private snapshot instead of returning externally
mutable data.

## Test

```sh
pekit test
```

| Test | Check |
|---|---|
| `peios-sys/unit` | `peios-sys`'s unit tests and its smoke test against libpeios |
| `peios-sys/uapi` | The same, with the kernel's types from `peios-uapi` |
| `peios/unit` | `peios`'s unit tests, smoke tests, and event snapshot test |
| `peios/uapi` | The same, with the `uapi` feature |

A test whose inputs did not change is found in the store and not run
again. Ordinary tests do not perform Peios identity or service operations
on the host. Pekit doesn't run documentation tests yet, so the guard tests
that reject sending or sharing impersonation guards run with Cargo.

## Building against peios-rs

peios-rs is a GCSL library as well as a workspace. A workspace whose crates
depend on its crates gives `peios-sys` what it needs, and its build scripts
libclang, and gives its programs libpeios when they run:

```text
import "github.com/gcslib/clang"
import "github.com/peios/peios-rs" as peios_rs

rust.workspace(..., crates = [...peios_rs.crate_settings()], libclang = [clang.libclang_18()])
rust.run_test(test, given = peios_rs.runtime(), env = peios_rs.runtime_env())
```

`peios-sys`'s build script gives only `peios-sys`'s own programs a run
path, so `runtime_env()` tells every other program where libpeios is.

A static program for `x86_64-unknown-linux-musl` enables the `peios`
crate's `static` feature and uses `static_musl_crate_settings()` in place
of `crate_settings()`. It links libpeios's static archive for musl, with
its private symbols renamed, and loads nothing at run time.

## Cargo

Cargo builds and tests peios-rs against an SDK laid out as an installed
one is. Pekit lays one out from the SDK's library:

```sh
pekit build tools/sdk
export PEIOS_SDK="$PWD/pekit-out/tools/sdk/laid_out/sdk"
```

Use an installed `peios.pc`, or set all of these variables:

```sh
export PEIOS_LIB_DIR="$PEIOS_SDK/lib"
export PEIOS_INCLUDE="$PEIOS_SDK/include"
export PKM_UAPI="$PEIOS_SDK/include"
export LD_LIBRARY_PATH="$PEIOS_SDK/lib"
export BINDGEN_EXTRA_CLANG_ARGS="-isystem $(cc -print-file-name=include)"
cargo +1.98.1 test --workspace --locked
cargo +1.98.1 test --workspace --features uapi --locked
```

`PKM_UAPI` is retained as a compatible environment-variable name; it points
to installed or snapshot headers, not a required PKM repository. The
explicit SDK path bypasses pkg-config version discovery, so supply matching
inputs. Do not rely on development run paths propagating into downstream
executables.

The `static` feature selects the C static archive. A Rust `std` executable
can conflict with that archive's embedded runtime. Check the feature with
`cargo check`; use dynamic linking for host tests and normal applications.

## Not built with pekit yet

The development source package, `dev.peios.peios-rs-devel`, and builds with
the native Peios toolchain, which hardens programs with control-flow
enforcement technology (CET), are not yet built with pekit. The packaging
pipeline and the native build settings from the Bazel build are kept
outside this repository until they are.

## Kernel input provenance

`vendor/kernel/ORIGIN.json` records the exact kernel commit and file hashes.
Run `python3 tools/update-kernel-inputs.py check` to verify that snapshot.
Replace it only through the updater, then review generated declarations and
rerun host, differential, and native checks. Do not format vendored inputs.

## Style and documentation

Use `tools/prepare-style-tools.py` with an output directory outside the
repository. Set `PEIOS_STYLE_BIN` to that directory, then run `tools/check`,
which checks style and the kernel inputs, runs the pekit tests, lays out a
development SDK, and runs Cargo's lints and tests against it. Set `TRAIL` to
the maintained Trail executable and run `tools/check-docs`. The optional
`--context ../learn` check validates publication links against the complete
merged documentation tree.
