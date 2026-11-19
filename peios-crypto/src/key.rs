//! Asymmetric keys, signing and verification.

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeySize, PublicEncryptingKey};
use aws_lc_rs::signature::{
    self as backend, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, ParsedPublicKey, RsaKeyPair,
    VerificationAlgorithm,
};

use crate::{Error, Result, Secret};

/// The kinds of key Peios offers. Keys of other kinds and sizes can be
/// neither generated nor imported. Generated RSA keys use the public
/// exponent 65537; imported ones keep whatever exponent the backend accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    /// ECDSA over NIST P-256.
    EcdsaP256,
    /// ECDSA over NIST P-384.
    EcdsaP384,
    /// RSA with a 2048-bit modulus.
    Rsa2048,
    /// RSA with a 3072-bit modulus.
    Rsa3072,
    /// RSA with a 4096-bit modulus.
    Rsa4096,
}

impl KeyAlgorithm {
    /// The scheme to sign with unless something requires another: ECDSA
    /// with the curve's matching hash, and RSASSA-PKCS1-v1_5 with SHA-256
    /// for RSA, which every X.509 verifier supports.
    pub fn default_signature_scheme(self) -> SignatureScheme {
        match self {
            Self::EcdsaP256 => SignatureScheme::EcdsaSha256,
            Self::EcdsaP384 => SignatureScheme::EcdsaSha384,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => SignatureScheme::RsaPkcs1Sha256,
        }
    }

    fn rsa_from_bits(bits: usize) -> Result<Self> {
        match bits {
            2048 => Ok(Self::Rsa2048),
            3072 => Ok(Self::Rsa3072),
            4096 => Ok(Self::Rsa4096),
            _ => Err(Error::Unsupported),
        }
    }
}

/// How a message is signed. ECDSA schemes are bound to their curve: SHA-256
/// with P-256 and SHA-384 with P-384, as the curves' strengths match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// ECDSA over P-256 with SHA-256, a DER `Ecdsa-Sig-Value`.
    EcdsaSha256,
    /// ECDSA over P-384 with SHA-384, a DER `Ecdsa-Sig-Value`.
    EcdsaSha384,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    RsaPssSha256,
}

impl SignatureScheme {
    /// Whether this scheme can be used with a key of `algorithm`.
    pub fn fits(self, algorithm: KeyAlgorithm) -> bool {
        match self {
            Self::EcdsaSha256 => algorithm == KeyAlgorithm::EcdsaP256,
            Self::EcdsaSha384 => algorithm == KeyAlgorithm::EcdsaP384,
            Self::RsaPkcs1Sha256 | Self::RsaPkcs1Sha384 | Self::RsaPssSha256 => matches!(
                algorithm,
                KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096
            ),
        }
    }

    fn verification(self) -> &'static dyn VerificationAlgorithm {
        match self {
            Self::EcdsaSha256 => &backend::ECDSA_P256_SHA256_ASN1,
            Self::EcdsaSha384 => &backend::ECDSA_P384_SHA384_ASN1,
            Self::RsaPkcs1Sha256 => &backend::RSA_PKCS1_2048_8192_SHA256,
            Self::RsaPkcs1Sha384 => &backend::RSA_PKCS1_2048_8192_SHA384,
            Self::RsaPssSha256 => &backend::RSA_PSS_2048_8192_SHA256,
        }
    }

    fn rsa_encoding(self) -> Option<&'static dyn backend::RsaEncoding> {
        match self {
            Self::RsaPkcs1Sha256 => Some(&backend::RSA_PKCS1_SHA256),
            Self::RsaPkcs1Sha384 => Some(&backend::RSA_PKCS1_SHA384),
            Self::RsaPssSha256 => Some(&backend::RSA_PSS_SHA256),
            Self::EcdsaSha256 | Self::EcdsaSha384 => None,
        }
    }
}

/// Something that signs on behalf of a key, which may live in software or
/// in hardware that never releases it.
pub trait Signer {
    /// The public half of the signing key.
    fn public_key(&self) -> &PublicKey;

    /// Signs `message` with `scheme`, which must fit the key.
    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>>;
}

/// A validated public key, held as its DER `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    spki: Vec<u8>,
    algorithm: KeyAlgorithm,
}

impl PublicKey {
    /// Accepts a DER `SubjectPublicKeyInfo` for a key Peios offers. Other
    /// encodings, such as a bare RSA key or EC point, are refused.
    pub fn from_spki(spki: &[u8]) -> Result<Self> {
        let curves = [
            (&backend::ECDSA_P256_SHA256_ASN1, KeyAlgorithm::EcdsaP256),
            (&backend::ECDSA_P384_SHA384_ASN1, KeyAlgorithm::EcdsaP384),
        ];
        for (verification, algorithm) in curves {
            if let Ok(parsed) = ParsedPublicKey::new(verification, spki) {
                return canonical(&parsed, spki, algorithm);
            }
        }
        let rsa = PublicEncryptingKey::from_der(spki).map_err(|_| Error::InvalidKey)?;
        let algorithm = KeyAlgorithm::rsa_from_bits(rsa.key_size_bits())?;
        let parsed = ParsedPublicKey::new(&backend::RSA_PKCS1_2048_8192_SHA256, spki)
            .map_err(|_| Error::InvalidKey)?;
        canonical(&parsed, spki, algorithm)
    }

    /// The key's algorithm and size.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// The DER `SubjectPublicKeyInfo`.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// Checks `signature` over `message` with `scheme`.
    pub fn verify(&self, scheme: SignatureScheme, message: &[u8], signature: &[u8]) -> Result<()> {
        if !scheme.fits(self.algorithm) {
            return Err(Error::IncompatibleScheme);
        }
        let parsed = ParsedPublicKey::new(scheme.verification(), &self.spki)
            .map_err(|_| Error::InvalidKey)?;
        parsed
            .verify_sig(message, signature)
            .map_err(|_| Error::VerificationFailed)
    }
}

/// Requires `input` to be exactly the canonical encoding of the parsed key,
/// so one key always has one representation.
fn canonical(parsed: &ParsedPublicKey, input: &[u8], algorithm: KeyAlgorithm) -> Result<PublicKey> {
    let der: PublicKeyX509Der<'static> = parsed.as_der().map_err(|_| Error::Backend)?;
    if der.as_ref() != input {
        return Err(Error::InvalidKey);
    }
    Ok(PublicKey {
        spki: input.to_vec(),
        algorithm,
    })
}

/// A private key held in this process's memory.
pub struct PrivateKey {
    pair: Pair,
    public: PublicKey,
}

enum Pair {
    Ecdsa(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

impl PrivateKey {
    /// Generates a new key.
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self> {
        let pair = match algorithm {
            KeyAlgorithm::EcdsaP256 => ecdsa_generate(&backend::ECDSA_P256_SHA256_ASN1_SIGNING)?,
            KeyAlgorithm::EcdsaP384 => ecdsa_generate(&backend::ECDSA_P384_SHA384_ASN1_SIGNING)?,
            KeyAlgorithm::Rsa2048 => rsa_generate(KeySize::Rsa2048)?,
            KeyAlgorithm::Rsa3072 => rsa_generate(KeySize::Rsa3072)?,
            KeyAlgorithm::Rsa4096 => rsa_generate(KeySize::Rsa4096)?,
        };
        Self::from_pair(pair)
    }

    /// Loads a PKCS #8 `PrivateKeyInfo` for a key Peios offers.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        let curves = [
            &backend::ECDSA_P256_SHA256_ASN1_SIGNING,
            &backend::ECDSA_P384_SHA384_ASN1_SIGNING,
        ];
        for signing in curves {
            if let Ok(pair) = EcdsaKeyPair::from_pkcs8(signing, der) {
                return Self::from_pair(Pair::Ecdsa(pair));
            }
        }
        let pair = RsaKeyPair::from_pkcs8(der).map_err(|_| Error::InvalidKey)?;
        Self::from_pair(Pair::Rsa(pair))
    }

    fn from_pair(pair: Pair) -> Result<Self> {
        let spki = match &pair {
            Pair::Ecdsa(pair) => spki_bytes(pair.public_key().as_der())?,
            Pair::Rsa(pair) => spki_bytes(pair.public_key().as_der())?,
        };
        let public = PublicKey::from_spki(&spki)?;
        Ok(Self { pair, public })
    }

    /// The key as a PKCS #8 `PrivateKeyInfo`. Hardware-held keys will not
    /// offer this.
    pub fn to_pkcs8(&self) -> Result<Secret> {
        let der = match &self.pair {
            Pair::Ecdsa(pair) => pair
                .to_pkcs8v1()
                .map_err(|_| Error::Backend)?
                .as_ref()
                .to_vec(),
            Pair::Rsa(pair) => {
                let der: Pkcs8V1Der<'static> = pair.as_der().map_err(|_| Error::Backend)?;
                der.as_ref().to_vec()
            }
        };
        Ok(Secret::new(der))
    }

    /// The key's algorithm and size.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.public.algorithm
    }
}

impl Signer for PrivateKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>> {
        if !scheme.fits(self.public.algorithm) {
            return Err(Error::IncompatibleScheme);
        }
        let random = SystemRandom::new();
        match (&self.pair, scheme.rsa_encoding()) {
            (Pair::Ecdsa(pair), None) => pair
                .sign(&random, message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| Error::Backend),
            (Pair::Rsa(pair), Some(encoding)) => {
                let mut signature = vec![0; pair.public_modulus_len()];
                pair.sign(encoding, &random, message, &mut signature)
                    .map_err(|_| Error::Backend)?;
                Ok(signature)
            }
            // `fits` has matched the scheme's family to the key's.
            _ => Err(Error::IncompatibleScheme),
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

fn ecdsa_generate(signing: &'static EcdsaSigningAlgorithm) -> Result<Pair> {
    EcdsaKeyPair::generate(signing)
        .map(Pair::Ecdsa)
        .map_err(|_| Error::Backend)
}

fn rsa_generate(size: KeySize) -> Result<Pair> {
    RsaKeyPair::generate(size)
        .map(Pair::Rsa)
        .map_err(|_| Error::Backend)
}

fn spki_bytes(
    der: std::result::Result<PublicKeyX509Der<'static>, aws_lc_rs::error::Unspecified>,
) -> Result<Vec<u8>> {
    der.map(|der| der.as_ref().to_vec())
        .map_err(|_| Error::Backend)
}
