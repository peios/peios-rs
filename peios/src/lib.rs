//! Safe, idiomatic Rust bindings to libpeios.
//!
//! This crate wraps the raw FFI in [`peios_sys`] with RAII handle types and
//! `Result`-returning methods. libpeios is consumed strictly as a C library
//! through its stable C ABI — never via its internal Rust crates.
#![warn(missing_docs)]

use peios_sys as sys;

// TODO: RAII wrappers over the opaque `peios_*` handles, and an Error type that
// maps libpeios' error codes (src/error.rs) into a `Result`. Sketch on request.

/// Placeholder so the crate compiles before the wrappers land.
#[doc(hidden)]
pub fn _link_check() {
    let _ = core::mem::size_of::<sys::peios_token>;
}
