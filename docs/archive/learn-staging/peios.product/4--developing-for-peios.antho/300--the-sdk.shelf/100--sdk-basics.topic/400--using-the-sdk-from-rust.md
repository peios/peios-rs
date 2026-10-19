---
title: Using the SDK from Rust
type: how-to
description: The Peios SDK ships first-class Rust bindings — the peios-sys raw FFI crate and the safe, idiomatic peios wrapper. This page is the on-ramp; the crate's rustdoc is the API reference.
related:
  - peios/sdk-conventions/library-conventions
  - peios/sdk-basics/installing-and-linking
  - peios/sdk-access-control/overview
---

The SDK is a C ABI, so it is reachable from any language with a C FFI — but Rust gets **first-class, maintained bindings** rather than hand-rolled `extern` blocks. If you are writing Rust on Peios, use them. This page is the on-ramp: what the crates are, how to wire them into a build, and where the docs live. It is deliberately *not* an API reference — that job belongs to the crate's rustdoc, which is generated from the code and so never drifts from it.

## The two crates

`peios-rs` is two crates, layered:

| Crate | What it is | Use it when |
|---|---|---|
| **`peios-sys`** | Raw, unsafe FFI. Bindings are generated at build time by `bindgen` from the hand-written `<peios.h>` (the shipping API, which the ABI verifier proves is identical to the Rust source). | You need the raw C surface — an escape hatch, or to build your own abstractions. |
| **`peios`** | The safe, idiomatic wrapper: RAII handle types, `Result`-returning methods, typed wire-constant families, and owned buffers — so you never touch a raw fd, a sticky-error builder, or a getxattr-style size probe directly. | Almost always. This is the crate you want. |

Both bind libpeios strictly as a **C library** through its stable ABI — they never depend on libpeios's internal Rust crates. The C ABI is the only supported entry point, and binding through it means the crates exercise the exact surface every other consumer uses.

The safe crate's modules mirror the libpeios concept headers one-for-one — `security`, `token`, `access`, `file`, `process`, `event`, `msgpack`, `registry` — so everything you learn about the C surface maps straight across.

## Where the docs live

Two places, and the split is deliberate:

- **The API reference is the crate's rustdoc.** Every public item in `peios` is documented (the crate is built with `#![warn(missing_docs)]`, so this is enforced), with a crate-level overview, per-module docs, and the error model. Build and browse it locally with:

  ```sh
  cargo doc -p peios --open
  ```

  This is the reference precisely *because* it is generated from the code — it can never fall out of sync with the actual method signatures and types the way hand-written prose would.

- **The concepts live in these docs.** The *what* and *why* — what a token is, how the [two-call protocol](~peios/sdk-conventions/the-two-call-buffer-protocol) works, how an [access check](~peios/sdk-access-control/checking-access) reaches a verdict, the [RSI source model](~peios/registry-sources/overview) — are identical whether you call from C or Rust, and they are documented once, here. The safe crate mirrors the concept headers, so each learn section maps to a module:

  | Rust module | Concepts in |
  |---|---|
  | `security`, `token`, `access`, `file`, `process` | [Access control](~peios/sdk-access-control/overview) |
  | `registry` | [The registry](~peios/sdk-registry/overview) |
  | `event`, `msgpack` | [Events](~peios/sdk-events/overview) |

  Read the concept page for the model, then the rustdoc for the exact Rust API.

## Adding the dependency

Add the `peios` crate to your `Cargo.toml`:

```toml
[dependencies]
peios = { git = "https://github.com/peios/peios-rs" }
```

(or a path/registry dependency, however you consume Peios crates). The features:

| Feature | Effect |
|---|---|
| *default* | Dynamic linking against `libpeios.so` — the intended production model (one soname-versioned system copy; fixes ship once). |
| `static` | Static linking against `libpeios.a`. See the [caveat below](#linking-dynamic-vs-static). |
| `uapi` | Reuse the canonical Rust mirror of the `pkm` UAPI types (`peios-uapi`) instead of letting `bindgen` emit its own copy, so the `kacs_*`/`pkm` types are one identity across crates. |

## A first taste

The safe crate turns the C conventions into ordinary Rust. Compare this with the C [first program](~peios/sdk-basics/your-first-program) — no size probes, no manual `close`, errors as `Result`:

```rust
use peios::token::{Token, TokenAccess};

fn main() -> peios::Result<()> {
    // Open my own token; the handle closes on drop.
    let me = Token::open_self(false, TokenAccess::QUERY)?;

    let sid = me.user()?;          // owned Sid, not a caller buffer + length
    let il  = me.integrity()?;     // typed IntegrityLevel, not a raw u32
    println!("running as {sid} at integrity {il:?}");

    Ok(())
}
```

The idiomatic wins show up most in the fiddly places. Impersonation, for instance, is an RAII guard — identity reverts when the guard drops, so it is exception-safe by construction rather than needing a manual `revert` in every cleanup path:

```rust
use std::os::fd::BorrowedFd;

fn serve(conn: BorrowedFd<'_>) -> peios::Result<()> {
    let caller = Token::open_peer(conn)?;
    let _guard = caller.impersonate_scoped()?;   // now acting as the caller
    do_work_as_caller()?;                        // any early return still reverts
    Ok(())
    // `_guard` drops here (or on the `?` above) → identity reverts automatically
}
```

Success-side status values — a file's opened-vs-created disposition, a key's created-new-vs-opened — come back *alongside* the handle, not as errors; genuine failures are the `Err(Error)` side, where `Error` wraps the `errno` the C ABI set.

## Linking: dynamic vs static

This is the one Rust-specific wrinkle worth understanding, because the static path has a sharp edge.

- **Dynamic (default)** links `libpeios.so` — the production model, and the path a normal `std` Rust program must use.
- **Static (`--features static`)** links `libpeios.a`. That archive is a Rust *staticlib*: it bakes in its own copy of the Rust runtime (the `panic = "abort"` handler, the global-allocator shim, the alloc-error handler). Linking it into a consumer that *also* carries that runtime — i.e. **any Rust binary that links `std`** — collides on those symbols (`rust_begin_unwind`, `__rust_alloc_error_handler`, …). So the static path is for **C consumers** and `no_std` Rust binaries that supply no conflicting runtime. A `std` Rust consumer — including `cargo test` — **must use the dynamic path.**

Keep that rule in mind and static linking is a non-issue: reach for it only from `no_std`, and use the default dynamic link everywhere else.

## Finding libpeios at build time

`peios-sys`'s build script resolves the library and headers in this order:

1. **Environment override** — set all three:
   - `PEIOS_LIB_DIR` — the directory containing `libpeios.{so,a}`
   - `PEIOS_INCLUDE` — the directory containing `<peios.h>`
   - `PKM_UAPI` — the directory containing `<pkm/*.h>` (referenced by `peios.h`'s signatures)
2. **pkg-config** — otherwise, if libpeios installs its `peios.pc` on `PKG_CONFIG_PATH`.
   The build requires the minimum libpeios version declared in
   `peios-sys/Cargo.toml` under `package.metadata.libpeios.minimum-version`.
   If the installed SDK is older, the build stops before generating bindings and
   reports the required and detected versions, instead of failing later with a
   missing Rust binding. A missing SDK reports the required version and setup
   guidance too. This applies to both dynamic and static linking.

The explicit environment override bypasses pkg-config, including its version
check. It remains useful for uninstalled development builds: you are responsible
for selecting compatible libpeios headers and a matching library at or above the
crate's declared minimum. The shipping headers do not expose a version macro,
so the build script cannot verify a version for this path.

On a system where libpeios is installed from its [packages](~peios/sdk-basics/installing-and-linking#the-packages), pkg-config just works and you set nothing. For a **local checkout**, point the three variables at your build tree:

```sh
PEIOS_LIB_DIR=../libpeios/target/release \
PEIOS_INCLUDE=../libpeios/include \
PKM_UAPI=../pkm/uapi \
cargo build
```

One bring-up gotcha for local dynamic builds: the crate bakes an rpath that resolves libpeios by its **soname** (`libpeios.so.0`), but a plain `cargo build` of libpeios emits only the unversioned `libpeios.so`. Create the soname link once so the run resolves:

```sh
ln -sf libpeios.so ../libpeios/target/release/libpeios.so.0
```

(This is a checkout convenience — on a real system the packaged `libpeios.so.0` is already there.)

## Privilege names

`peios::security::Privileges` exposes the published kernel privileges,
including `TAKE_OWNERSHIP`, `SYSTEM_PROFILE` and `RELABEL`. Their
canonical names are `SeTakeOwnershipPrivilege`,
`SeSystemProfilePrivilege` and `SeRelabelPrivilege`. Use `parse_name`
for a canonical name and `canonical_names` to enumerate a mask in bit
order. Names are case-sensitive; an unknown name returns `None`.

The values come from the kernel ABI constants. Naming a privilege does
not grant it: the token must hold it and the operation's privilege
rules still apply. The retired `SeBindPrivilegedPortPrivilege` is not
accepted.

For checkout builds, use the versioned `pkm/uapi` source headers rather
than an old `out/build/headers` installation. With the `uapi` feature,
peios-sys pins the same peios-uapi revision as libpeios.

## The bottom line

- Depend on the **`peios`** crate; drop to `peios-sys` only for the raw surface.
- **Concepts:** these docs. **API reference:** `cargo doc -p peios --open`.
- Use the **default dynamic** link unless you are `no_std`.

Everything the [library conventions](~peios/sdk-conventions/library-conventions) page teaches still holds underneath — the crate just wraps it in Rust idiom.
