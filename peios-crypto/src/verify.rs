//! Verification of signatures made outside Peios, such as the signature on
//! a certificate request.
//!
//! [`PublicKey`] stays strict because it describes keys Peios creates and
//! signs with. Signatures from other software arrive in more shapes, so
//! [`VerifyingKey`] accepts a wider set of keys and pairings, for
//! verification only.

use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use aws_lc_rs::rsa::PublicEncryptingKey;
use aws_lc_rs::signature::{self as backend, ParsedPublicKey};

use crate::digest::Algorithm as Hash;
use crate::{Error, PublicKey, Result};

/// The smallest RSA modulus a [`VerifyingKey`] accepts.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;
/// The largest RSA modulus a [`VerifyingKey`] accepts, the limit of the
/// backend's RSA verifiers.
pub const MAX_RSA_MODULUS_BITS: usize = 8192;

/// DER's SEQUENCE tag, the first byte of every `SubjectPublicKeyInfo`.
const DER_SEQUENCE: u8 = 0x30;

/// How a signature was made. The key supplies the rest: an ECDSA
/// signature's curve is the key's curve.
///
/// SHA-1 isn't offered: Peios crypto policy has to grade it first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationAlgorithm {
    /// ECDSA with this hash, a DER `Ecdsa-Sig-Value`. Any of the hashes can
    /// be used with either curve, as other software commonly does.
    Ecdsa(Hash),
    /// RSASSA-PKCS1-v1_5 with this hash.
    RsaPkcs1(Hash),
    /// RSASSA-PSS with this hash, MGF1 with the same hash, and a salt as long
    /// as the hash. Signatures with any other salt length don't verify.
    RsaPss(Hash),
}

/// The kind of key a [`VerifyingKey`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyingKeyKind {
    /// ECDSA over NIST P-256.
    EcdsaP256,
    /// ECDSA over NIST P-384.
    EcdsaP384,
    /// RSA, with the modulus size in bits.
    Rsa {
        /// The modulus size, from [`MIN_RSA_MODULUS_BITS`] to
        /// [`MAX_RSA_MODULUS_BITS`].
        modulus_bits: usize,
    },
}

/// A public key accepted for verifying signatures made elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    spki: Vec<u8>,
    kind: VerifyingKeyKind,
}

impl VerifyingKey {
    /// Accepts a DER `SubjectPublicKeyInfo` for an ECDSA P-256 or P-384 key,
    /// with its point compressed or not, or for an RSA key with a modulus
    /// within the accepted range. A bare key outside a
    /// `SubjectPublicKeyInfo` is refused.
    pub fn from_spki(spki: &[u8]) -> Result<Self> {
        if spki.first() != Some(&DER_SEQUENCE) {
            return Err(Error::InvalidKey);
        }
        let curves = [
            (
                &backend::ECDSA_P256_SHA256_ASN1,
                VerifyingKeyKind::EcdsaP256,
            ),
            (
                &backend::ECDSA_P384_SHA384_ASN1,
                VerifyingKeyKind::EcdsaP384,
            ),
        ];
        for (verification, kind) in curves {
            if let Ok(parsed) = ParsedPublicKey::new(verification, spki) {
                return Self::from_parsed(&parsed, kind);
            }
        }
        // The backend checks the RSA size itself and says when that's why it
        // refused, which is a supported-size question rather than bad data.
        let rsa = PublicEncryptingKey::from_der(spki).map_err(|rejected| {
            match rejected.description_() {
                "TooSmall" | "TooLarge" => Error::Unsupported,
                _ => Error::InvalidKey,
            }
        })?;
        let modulus_bits = rsa.key_size_bits();
        if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&modulus_bits) {
            return Err(Error::Unsupported);
        }
        let parsed = ParsedPublicKey::new(&backend::RSA_PKCS1_2048_8192_SHA256, spki)
            .map_err(|_| Error::InvalidKey)?;
        Self::from_parsed(&parsed, VerifyingKeyKind::Rsa { modulus_bits })
    }

    fn from_parsed(parsed: &ParsedPublicKey, kind: VerifyingKeyKind) -> Result<Self> {
        let der: PublicKeyX509Der<'static> = parsed.as_der().map_err(|_| Error::Backend)?;
        Ok(Self {
            spki: der.as_ref().to_vec(),
            kind,
        })
    }

    /// The kind of key.
    pub fn kind(&self) -> VerifyingKeyKind {
        self.kind
    }

    /// The key's canonical DER `SubjectPublicKeyInfo`, with an EC point
    /// uncompressed, whatever encoding it was read from.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// Checks `signature` over `message`, made with `algorithm`.
    pub fn verify(
        &self,
        algorithm: VerificationAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let backend = backend_algorithm(self.kind, algorithm).ok_or(Error::IncompatibleScheme)?;
        let parsed = ParsedPublicKey::new(backend, &self.spki).map_err(|_| Error::InvalidKey)?;
        parsed
            .verify_sig(message, signature)
            .map_err(|_| Error::VerificationFailed)
    }
}

impl From<&PublicKey> for VerifyingKey {
    fn from(key: &PublicKey) -> Self {
        Self::from_spki(key.spki()).expect("a PublicKey is always a valid verifying key")
    }
}

fn backend_algorithm(
    kind: VerifyingKeyKind,
    algorithm: VerificationAlgorithm,
) -> Option<&'static dyn backend::VerificationAlgorithm> {
    use VerificationAlgorithm::{Ecdsa, RsaPkcs1, RsaPss};
    use VerifyingKeyKind::{EcdsaP256, EcdsaP384, Rsa};
    Some(match (kind, algorithm) {
        (EcdsaP256, Ecdsa(Hash::Sha256)) => &backend::ECDSA_P256_SHA256_ASN1,
        (EcdsaP256, Ecdsa(Hash::Sha384)) => &backend::ECDSA_P256_SHA384_ASN1,
        (EcdsaP256, Ecdsa(Hash::Sha512)) => &backend::ECDSA_P256_SHA512_ASN1,
        (EcdsaP384, Ecdsa(Hash::Sha256)) => &backend::ECDSA_P384_SHA256_ASN1,
        (EcdsaP384, Ecdsa(Hash::Sha384)) => &backend::ECDSA_P384_SHA384_ASN1,
        (EcdsaP384, Ecdsa(Hash::Sha512)) => &backend::ECDSA_P384_SHA512_ASN1,
        (Rsa { .. }, RsaPkcs1(Hash::Sha256)) => &backend::RSA_PKCS1_2048_8192_SHA256,
        (Rsa { .. }, RsaPkcs1(Hash::Sha384)) => &backend::RSA_PKCS1_2048_8192_SHA384,
        (Rsa { .. }, RsaPkcs1(Hash::Sha512)) => &backend::RSA_PKCS1_2048_8192_SHA512,
        (Rsa { .. }, RsaPss(Hash::Sha256)) => &backend::RSA_PSS_2048_8192_SHA256,
        (Rsa { .. }, RsaPss(Hash::Sha384)) => &backend::RSA_PSS_2048_8192_SHA384,
        (Rsa { .. }, RsaPss(Hash::Sha512)) => &backend::RSA_PSS_2048_8192_SHA512,
        _ => return None,
    })
}
