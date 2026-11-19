use std::fmt;

use zeroize::Zeroizing;

/// Secret bytes: a private key, a passphrase or unsealed data.
///
/// The bytes are overwritten when the value is dropped, and `Debug` never
/// prints them, so a secret cannot leak through a log line by accident.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Takes ownership of `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The secret bytes. Copy them nowhere that outlives this value.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl From<String> for Secret {
    fn from(text: String) -> Self {
        Self::new(text.into_bytes())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(..)")
    }
}
