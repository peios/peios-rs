//! Peios cryptography for Rust programs.
//!
//! This crate is how Peios-authored Rust code gets cryptography: keys and
//! signatures, passphrase sealing for keys at rest, and the building blocks
//! of random bytes, digests and HMAC. Its menus are closed on purpose. Only
//! the key sizes and signature schemes Peios offers can be chosen, secrets
//! are wiped when dropped, and MACs are compared in constant time.
//!
//! # Interim backend
//!
//! This version calls aws-lc-rs and RustCrypto's `argon2` directly and does
//! **not yet enforce Peios crypto policy**: [`Error::PolicyRejected`] is
//! never returned. Peios will move the crate onto libpeios-crypto, the
//! policy-enforcing system library, without changing this API. Handle
//! `PolicyRejected` now so that callers keep working when it arrives.
//!
//! # Layout
//!
//! - [`PrivateKey`], [`PublicKey`] and [`Signer`]: keys, signing and
//!   verification.
//! - [`VerifyingKey`]: verifying signatures made by other software, such as
//!   certificate requests, which use a wider range of keys and pairings.
//! - [`seal_with_passphrase`] and [`open_with_passphrase`]: protecting a
//!   secret at rest under a passphrase.
//! - [`pkcs12`]: writing a key and its certificates for other software.
//! - [`random`], [`digest`] and [`hmac`]: building blocks.
#![warn(missing_docs)]

mod error;
mod key;
mod seal;
mod secret;
mod verify;

pub mod digest;
pub mod hmac;
pub mod pkcs12;
pub mod random;

pub use error::{Error, Result};
pub use key::{KeyAlgorithm, PrivateKey, PublicKey, SignatureScheme, Signer};
pub use seal::{open_with_passphrase, seal_with_passphrase};
pub use secret::Secret;
pub use verify::{
    VerificationAlgorithm, VerifyingKey, VerifyingKeyKind, MAX_RSA_MODULUS_BITS,
    MIN_RSA_MODULUS_BITS,
};
