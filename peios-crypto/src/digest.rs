//! SHA-2 message digests.

/// A digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// SHA-256, a 32-byte digest.
    Sha256,
    /// SHA-384, a 48-byte digest.
    Sha384,
    /// SHA-512, a 64-byte digest.
    Sha512,
}

impl Algorithm {
    fn backend(self) -> &'static aws_lc_rs::digest::Algorithm {
        match self {
            Self::Sha256 => &aws_lc_rs::digest::SHA256,
            Self::Sha384 => &aws_lc_rs::digest::SHA384,
            Self::Sha512 => &aws_lc_rs::digest::SHA512,
        }
    }

    /// The digest's length in bytes.
    pub fn output_len(self) -> usize {
        self.backend().output_len()
    }
}

/// The digest of `data`.
pub fn digest(algorithm: Algorithm, data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(algorithm.backend(), data)
        .as_ref()
        .to_vec()
}

/// A digest computed over data supplied in pieces.
pub struct Hasher(aws_lc_rs::digest::Context);

impl Hasher {
    /// Starts a digest with `algorithm`.
    pub fn new(algorithm: Algorithm) -> Self {
        Self(aws_lc_rs::digest::Context::new(algorithm.backend()))
    }

    /// Adds `data` to the digest.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything supplied.
    pub fn finish(self) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }
}
