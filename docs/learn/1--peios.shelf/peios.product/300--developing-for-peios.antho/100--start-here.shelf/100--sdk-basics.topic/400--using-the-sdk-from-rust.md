---
title: Using the SDK from Rust
type: how-to
description: Link a Rust application to the Peios C SDK and use owned handles.
---

Use the `peios` crate to access Peios through Rust handles and `Result`
values. The `peios-sys` crate exposes the underlying unsafe C functions.
Both use the public C application binary interface (ABI).

## Before you start

- Install Rust and Cargo.
- Install matching libpeios headers and libraries, version 0.5.12 or later.
- Install pkg-config and libclang for binding generation.
- Place the `peios-rs` checkout beside your application for this example.
- Run token operations on a Peios kernel.

## Add the dependency

1. Add a local dependency to your application's `Cargo.toml`:

   ```toml
   [dependencies]
   peios = { path = "../peios-rs/peios" }
   ```

2. Create `src/main.rs`:

   ```rust
   use peios::token::{Token, TokenAccess};

   fn main() -> peios::Result<()> {
       let token = Token::open_self(false, TokenAccess::QUERY)?;
       let identity = token.user()?;
       println!("identity: {identity}");
       Ok(())
   }
   ```

3. Run `cargo run`. The token handle closes when it leaves scope.

## Check the result

The program prints the caller's security identifier (SID). A native-call
error on another kernel does not indicate a successful Peios access check.

Generate the API reference with `cargo doc -p peios --open` from the SDK
checkout. The repository's `docs/building.md` covers SDK discovery and
host tests.

## Linking and types

Use dynamic linking for ordinary Rust applications. The C static archive
contains its own Rust runtime, which can conflict with a Rust executable's
runtime. The `static` feature only selects that archive; it does not remove
those conflicts.

The optional `uapi` feature re-exports kernel types through `peios_sys`.
Those types come from the recorded kernel snapshot. Import them through
that re-export when sharing values with these bindings: a separately
compiled copy of the same structure has a different Rust type identity.

## Identity and event ownership

A scoped impersonation guard belongs to the thread that creates it. Rust
rejects moving or sharing the guard across threads. Keep identity-dependent
work on that thread, and call `revert` when you need to check restoration.
Dropping the guard attempts restoration but cannot return an error.
Impersonations do not nest: restoration clears the impersonation rather
than restoring an earlier impersonated identity.

Events own their type names and payloads. You can retain them after the
next read or after closing the reader. A low-level read returns `EAGAIN`
if its slot is empty, overwritten, or changes generation during copying.
After a generation change, attach and map the ring again.

Event emission checks names, payload lengths, and batch counts before
converting them to the C ABI's fixed-width fields. Values that do not fit
return `EINVAL`. Socket receive calls also reject an unrepresentable handle
capacity before allocating its buffer or consuming a message.

## Access checks and request identity

[Audit Contexts in Rust](~peios/sdk-basics/audit-contexts-in-rust) explains
object descriptions and denial results.
[Token Messages in Rust](~peios/sdk-basics/token-messages-in-rust) covers
received-handle ownership, truncation, and explicit peer-identity fallback.
