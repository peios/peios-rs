# Building and Testing peios-rs

Run commands from this repository. The `bazel` launcher verifies Bazel 8.4.2;
Bazel pins the language toolchains and dependency graph. Development checks
also use the host C compiler, Python 3.11 or later, and libclang where bindings
are generated. These host dependencies are not a hermetic Peios toolchain.

## Host checks

Set `PEIOS_SDK` to an absolute SDK root containing matching `include/peios.h`,
`include/pkm`, and `lib/libpeios.so.0`. Use libpeios 0.5.12 or later: its event
reader keeps a private snapshot instead of returning externally mutable data.

```sh
./bazel test //...
```

The `peios-sys:uapi-tests` target checks the recorded kernel type feature.
Guard documentation tests reject sending or sharing impersonation guards.
Ordinary tests do not perform Peios identity or service operations on the host.

For Cargo, use an installed `peios.pc`, or set all of these variables:

```sh
export PEIOS_LIB_DIR="$PEIOS_SDK/lib"
export PEIOS_INCLUDE="$PEIOS_SDK/include"
export PKM_UAPI="$PEIOS_SDK/include"
export LD_LIBRARY_PATH="$PEIOS_SDK/lib"
export BINDGEN_EXTRA_CLANG_ARGS="-isystem $(cc -print-file-name=include)"
cargo +1.98.1 test --workspace --locked
cargo +1.98.1 test --workspace --features uapi --locked
```

`PKM_UAPI` is retained as a compatible environment-variable name; it points to
installed or snapshot headers, not a required PKM repository. The explicit
SDK path bypasses pkg-config version discovery, so supply matching inputs.
Do not rely on development rpaths propagating into downstream executables.

The `static` feature selects the C static archive. A Rust `std` executable can
conflict with that archive's embedded runtime. Check the feature with
`cargo check`; use dynamic linking for host tests and normal applications.

## Reference SDK fixture

Build a matched development C SDK from the consolidated repository:

```sh
python3 tools/prepare-dev-sdk.py ../peios-sdk /absolute/path/to/sdk-fixture
export PEIOS_SDK=/absolute/path/to/sdk-fixture
```

The destination must be new. The helper builds the shared library and static
archive with Bazel, copies the matching headers, and records file hashes,
source revision, and checkout changes in `provenance.json`.

## Packages

```sh
./bazel build //:packages
```

The output under `bazel-bin/packages/store.store` contains canonical manifests,
compressed content-addressed blobs, and a provenance index. The package holds
SDK source, licenses, build definitions, and maintained documentation. It does
not bundle third-party compiler caches or an installed compiler.

The package is `dev.peios.peios-rs-devel`, version
`0.4.0-1`, architecture `noarch`. It installs source under
`/usr/src/rust/peios-rs`.
Cargo manifests retain the individual crate versions: `peios` 0.4.0 and `peios-sys` 0.3.0.

Provenance marks these packages as development output, not release-qualified
artifacts. Kernel VM tests and release-image qualification remain separate.

## Kernel input provenance

`vendor/kernel/ORIGIN.json` records the exact kernel commit and file hashes.
Run `python3 tools/update-kernel-inputs.py check` to verify that snapshot.
Replace it only through the updater, then review generated declarations and
rerun host, differential, and native checks. Do not format vendored inputs.

## Style and documentation

Use `tools/prepare-style-tools.py` with an output directory outside the repository.
Set `PEIOS_STYLE_BIN` to that directory, then run `tools/check`.
Set `TRAIL` to the maintained Trail executable and run `tools/check-docs`.
The optional `--context ../panorama/docs` check validates publication links
against the complete merged documentation tree.
