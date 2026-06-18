# peios-rs

Rust bindings to **libpeios**, the Peios userspace C ABI library.

These crates treat libpeios as a **C library** — they bind to its stable C ABI
via FFI and link the compiled `libpeios.{so,a}`. They deliberately do **not**
depend on libpeios' internal Rust crates (`kacs-core`, etc.); the C ABI is the
only supported entry point, and binding through it dogfoods the exact surface C
consumers use. (pkm uapi types are the one shared exception — see below.)

## Crates

- **`peios-sys`** — raw, unsafe FFI. Bindings are generated at build time by
  bindgen from the hand-written `<peios.h>` (libpeios' shipping API, which
  `verify-abi.sh` proves is ABI-identical to the Rust source).
- **`peios`** — safe, idiomatic wrapper (RAII handles, `Result` errors).

## Linking

`libpeios` ships both a `cdylib` and a `staticlib`, so either works:

- **Dynamic (default)** — links `libpeios.so`. The intended production model:
  one system copy, soname-versioned, fixes ship once. The ABI-stability
  machinery in libpeios exists to support this.
- **Static (`--features static`)** — links `libpeios.a` into a self-contained
  binary. Use during bring-up (no installed `libpeios.so` on the system yet),
  for tooling, and for reproducible test binaries.

## Finding libpeios at build time

`peios-sys/build.rs` resolves the library and headers in this order:

1. **Env override** — set all three:
   - `PEIOS_LIB_DIR` — dir containing `libpeios.{so,a}`
   - `PEIOS_INCLUDE` — dir containing `<peios.h>`
   - `PKM_UAPI` — dir containing `<pkm/*.h>` (referenced by peios.h signatures)
2. **pkg-config** — if libpeios installs a `peios.pc` on `PKG_CONFIG_PATH`.

For a local checkout, that's typically:

```sh
PEIOS_LIB_DIR=../libpeios/target/release \
PEIOS_INCLUDE=../libpeios/include \
PKM_UAPI=../pkm/uapi \
cargo build
```

Dynamic dev builds bake an rpath to `PEIOS_LIB_DIR` so test binaries run without
`LD_LIBRARY_PATH`. That's a bring-up convenience — remove it once libpeios lives
on a real system library path.

## The `uapi` feature

libpeios' function signatures reference pkm uapi types (`kacs_*`, `pkm_*`).
Without `uapi`, bindgen emits its own copies (self-contained, but a distinct
Rust identity from anything else). With `--features uapi`, those types are
blocklisted in bindgen and re-exported from `peios-uapi` — the same generated
mirror libpeios consumes, pinned to the same pkm rev — so they have a single
identity across libpeios, peios-uapi, and consumers.
