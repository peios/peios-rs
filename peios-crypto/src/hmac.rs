//! HMAC message authentication.

use crate::{Error, Result};

/// The hash an HMAC is built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-384.
    Sha384,
    /// HMAC-SHA-512.
    Sha512,
}

/// An HMAC key.
pub struct Key(aws_lc_rs::hmac::Key);

impl Key {
    /// A key for `algorithm` from the secret bytes `key`.
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        let backend = match algorithm {
            Algorithm::Sha256 => aws_lc_rs::hmac::HMAC_SHA256,
            Algorithm::Sha384 => aws_lc_rs::hmac::HMAC_SHA384,
            Algorithm::Sha512 => aws_lc_rs::hmac::HMAC_SHA512,
        };
        Self(aws_lc_rs::hmac::Key::new(backend, key))
    }
}

/// The MAC of `data` under `key`.
pub fn sign(key: &Key, data: &[u8]) -> Vec<u8> {
    aws_lc_rs::hmac::sign(&key.0, data).as_ref().to_vec()
}

/// Checks `tag` against the MAC of `data` in constant time. Never compare
/// MACs with `==`, which can reveal how much of a forged tag was right.
pub fn verify(key: &Key, data: &[u8], tag: &[u8]) -> Result<()> {
    aws_lc_rs::hmac::verify(&key.0, data, tag).map_err(|_| Error::VerificationFailed)
}
