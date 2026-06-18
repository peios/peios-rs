//! Raw FFI bindings to libpeios. No safety, no ergonomics — that's `peios`'s job.
//!
//! Bindings are generated at build time by bindgen from the hand-written
//! `<peios.h>` umbrella header (the shipping API that `verify-abi.sh` proves is
//! ABI-identical to libpeios' Rust source). See `build.rs`.
#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
