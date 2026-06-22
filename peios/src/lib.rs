//! Safe, idiomatic Rust bindings to libpeios.
//!
//! libpeios is the foundational Peios userspace C library that sits beside
//! glibc. This crate wraps its stable C ABI (via the raw [`peios_sys`] bindings)
//! in RAII handle types, `Result`-returning methods, typed wire-constant
//! families, and owned buffers — so Rust code on Peios never touches a raw fd,
//! a sticky-error builder, or a getxattr-style size probe directly.
//!
//! libpeios is consumed strictly as a C library through its stable C ABI — never
//! via its internal Rust crates.
//!
//! # Layout
//!
//! The modules mirror the libpeios concept headers:
//!
//! - [`security`] — SIDs, access masks, privileges, ACLs, and security
//!   descriptors (the KACS vocabulary every other module speaks).
//! - [`token`] — access tokens, the token-spec builder, and logon sessions.
//! - [`access`] — KACS access checks.
//! - [`file`](mod@file) — native KACS file open and security-descriptor I/O.
//! - [`process`] — process-security (mitigation) controls.
//! - [`event`] — KMES event emission and consumption.
//! - [`msgpack`] — the MessagePack codec for event payloads.
//! - [`registry`] — LCS, the layered configuration registry.
//!
//! # Errors
//!
//! Every fallible call returns [`Result`], whose error ([`Error`]) is an OS error
//! captured from `errno`. Success-side status values (a file's opened/created
//! disposition, a key's created-new/opened-existing disposition) are returned
//! alongside the handle, not as errors.
#![warn(missing_docs)]

mod error;
mod util;

pub mod access;
pub mod event;
pub mod file;
pub mod msgpack;
pub mod process;
pub mod registry;
pub mod security;
pub mod token;

pub use error::{Error, Result};
