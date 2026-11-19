use std::fmt;

/// Why a cryptographic operation failed.
///
/// The variants deliberately reveal little. In particular a wrong passphrase
/// and a damaged sealed blob are one error, because telling them apart helps
/// an attacker guessing passphrases more than it helps a user.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Peios crypto policy refuses this algorithm for this operation. The
    /// interim backend never returns it; callers should handle it anyway.
    PolicyRejected {
        /// The algorithm's policy identifier, such as `md5`.
        algorithm: &'static str,
        /// The operation's policy identifier, such as `sign`.
        operation: &'static str,
    },
    /// Key data is malformed, or encodes a key of a kind Peios does not offer.
    InvalidKey,
    /// The algorithm, size or scheme is not one Peios offers.
    Unsupported,
    /// The signature scheme does not fit the key, such as an RSA scheme with
    /// an ECDSA key, or SHA-384 with a P-256 key.
    IncompatibleScheme,
    /// A signature or MAC did not verify.
    VerificationFailed,
    /// The data is not a sealed blob, or uses a format version this build
    /// does not read.
    MalformedSealed,
    /// The passphrase is wrong, or the sealed blob was damaged or altered.
    WrongPassphraseOrDamaged,
    /// The backend failed unexpectedly, for example to obtain randomness.
    Backend,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyRejected {
                algorithm,
                operation,
            } => {
                write!(
                    formatter,
                    "crypto policy refuses {algorithm} for {operation}"
                )
            }
            Self::InvalidKey => formatter.write_str("invalid or unsupported key"),
            Self::Unsupported => formatter.write_str("unsupported algorithm"),
            Self::IncompatibleScheme => {
                formatter.write_str("signature scheme does not fit the key")
            }
            Self::VerificationFailed => formatter.write_str("verification failed"),
            Self::MalformedSealed => formatter.write_str("not a supported sealed blob"),
            Self::WrongPassphraseOrDamaged => {
                formatter.write_str("wrong passphrase, or the sealed data is damaged")
            }
            Self::Backend => formatter.write_str("cryptographic backend failure"),
        }
    }
}

impl std::error::Error for Error {}

/// The result of a cryptographic operation.
pub type Result<T> = std::result::Result<T, Error>;
