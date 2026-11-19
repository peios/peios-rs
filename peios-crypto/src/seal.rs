//! Passphrase sealing: protecting a secret, such as a CA's private key, at
//! rest under a passphrase.
//!
//! A sealed blob is Peios's own format, version 1:
//!
//! | Offset | Size | Field                                              |
//! |-------:|-----:|----------------------------------------------------|
//! |      0 |    8 | magic, ASCII `PEIOSEAL`                            |
//! |      8 |    1 | format version, 1                                  |
//! |      9 |    1 | key derivation, 1 = Argon2id version 0x13          |
//! |     10 |    4 | Argon2 memory in KiB, big-endian                   |
//! |     14 |    4 | Argon2 passes, big-endian                          |
//! |     18 |    4 | Argon2 lanes, big-endian                           |
//! |     22 |    1 | salt length, 16                                    |
//! |     23 |   16 | salt                                               |
//! |     39 |    1 | cipher, 1 = AES-256-GCM                            |
//! |     40 |   12 | nonce                                              |
//! |     52 |    … | ciphertext, then the 16-byte GCM tag               |
//!
//! The 52-byte header is the AEAD's associated data, so altering any
//! parameter makes opening fail rather than weakening the derivation. Each
//! seal draws a fresh salt, and so a fresh key, which makes the random nonce
//! safe. The derivation identifier leaves room for PBKDF2 under FIPS.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use zeroize::Zeroizing;

use crate::{random, Error, Result, Secret};

const MAGIC: &[u8; 8] = b"PEIOSEAL";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_AES_256_GCM: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 52;

/// The parameters every seal uses: RFC 9106 §4's second recommended
/// option, 64 MiB of memory, three passes and four lanes.
const SEAL_PARAMETERS: Argon2Parameters = Argon2Parameters {
    memory_kib: 64 * 1024,
    passes: 3,
    lanes: 4,
};

/// Upper bounds on parameters read from a blob, so that opening a hostile
/// blob cannot demand gigabytes of memory or hours of work. The header is
/// authenticated, but only after the costly derivation has run.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_PASSES: u32 = 16;
const MAX_LANES: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Argon2Parameters {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

/// Seals `secret` under `passphrase`. The library sets no minimum passphrase
/// strength; callers that protect valuable keys must enforce one.
pub fn seal_with_passphrase(secret: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    seal_with(secret, passphrase, SEAL_PARAMETERS)
}

fn seal_with(secret: &[u8], passphrase: &[u8], parameters: Argon2Parameters) -> Result<Vec<u8>> {
    let mut salt = [0; SALT_LEN];
    random::fill(&mut salt)?;
    let mut nonce = [0; NONCE_LEN];
    random::fill(&mut nonce)?;

    let mut blob = Vec::with_capacity(HEADER_LEN + secret.len() + TAG_LEN);
    blob.extend_from_slice(MAGIC);
    blob.push(FORMAT_VERSION);
    blob.push(KDF_ARGON2ID);
    blob.extend_from_slice(&parameters.memory_kib.to_be_bytes());
    blob.extend_from_slice(&parameters.passes.to_be_bytes());
    blob.extend_from_slice(&parameters.lanes.to_be_bytes());
    blob.push(SALT_LEN as u8);
    blob.extend_from_slice(&salt);
    blob.push(CIPHER_AES_256_GCM);
    blob.extend_from_slice(&nonce);

    let key = derive_key(passphrase, &salt, parameters)?;
    let mut sealed = Zeroizing::new(secret.to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&blob[..HEADER_LEN]),
        &mut *sealed,
    )
    .map_err(|_| Error::Backend)?;
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Opens a blob sealed by [`seal_with_passphrase`].
pub fn open_with_passphrase(sealed: &[u8], passphrase: &[u8]) -> Result<Secret> {
    let header = Header::parse(sealed)?;
    let key = derive_key(passphrase, &header.salt, header.parameters)?;
    let mut buffer = Zeroizing::new(sealed[HEADER_LEN..].to_vec());
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(header.nonce),
            Aad::from(&sealed[..HEADER_LEN]),
            &mut buffer,
        )
        .map_err(|_| Error::WrongPassphraseOrDamaged)?;
    Ok(Secret::from(&*plaintext))
}

struct Header {
    parameters: Argon2Parameters,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn parse(blob: &[u8]) -> Result<Self> {
        if blob.len() < HEADER_LEN + TAG_LEN || &blob[..8] != MAGIC {
            return Err(Error::MalformedSealed);
        }
        if blob[8] != FORMAT_VERSION || blob[9] != KDF_ARGON2ID || blob[39] != CIPHER_AES_256_GCM {
            return Err(Error::MalformedSealed);
        }
        if usize::from(blob[22]) != SALT_LEN {
            return Err(Error::MalformedSealed);
        }
        let word = |at: usize| u32::from_be_bytes(blob[at..at + 4].try_into().expect("4 bytes"));
        let parameters = Argon2Parameters {
            memory_kib: word(10),
            passes: word(14),
            lanes: word(18),
        };
        let within_bounds = parameters.memory_kib <= MAX_MEMORY_KIB
            && (1..=MAX_PASSES).contains(&parameters.passes)
            && (1..=MAX_LANES).contains(&parameters.lanes);
        if !within_bounds {
            return Err(Error::MalformedSealed);
        }
        Ok(Self {
            parameters,
            salt: blob[23..39].try_into().expect("16 bytes"),
            nonce: blob[40..HEADER_LEN].try_into().expect("12 bytes"),
        })
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8], parameters: Argon2Parameters) -> Result<LessSafeKey> {
    let argon2_parameters = argon2::Params::new(
        parameters.memory_kib,
        parameters.passes,
        parameters.lanes,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::MalformedSealed)?;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_parameters,
    );
    let mut key = Zeroizing::new([0; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|_| Error::Backend)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &*key).map_err(|_| Error::Backend)?;
    Ok(LessSafeKey::new(unbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small parameters keep the unit tests fast; one test below uses the
    /// real ones.
    const TEST_PARAMETERS: Argon2Parameters = Argon2Parameters {
        memory_kib: 64,
        passes: 1,
        lanes: 1,
    };

    #[test]
    fn sealed_secret_opens_with_its_passphrase() {
        let blob = seal_with(b"root key", b"correct horse", TEST_PARAMETERS).unwrap();
        let opened = open_with_passphrase(&blob, b"correct horse").unwrap();
        assert_eq!(opened.expose(), b"root key");
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        let blob = seal_with(b"root key", b"correct horse", TEST_PARAMETERS).unwrap();
        let result = open_with_passphrase(&blob, b"battery staple");
        assert_eq!(result.unwrap_err(), Error::WrongPassphraseOrDamaged);
    }

    #[test]
    fn header_records_the_format_and_parameters() {
        let blob = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        assert_eq!(&blob[..8], b"PEIOSEAL");
        assert_eq!(blob[8..10], [FORMAT_VERSION, KDF_ARGON2ID]);
        assert_eq!(blob[10..14], 64u32.to_be_bytes());
        assert_eq!(blob[14..18], 1u32.to_be_bytes());
        assert_eq!(blob[18..22], 1u32.to_be_bytes());
        assert_eq!(blob[22], 16);
        assert_eq!(blob[39], CIPHER_AES_256_GCM);
        assert_eq!(blob.len(), HEADER_LEN + b"root key".len() + TAG_LEN);
    }

    #[test]
    fn altered_parameters_cannot_weaken_the_derivation() {
        let mut blob = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        blob[13] = 32;
        let result = open_with_passphrase(&blob, b"pass");
        assert_eq!(result.unwrap_err(), Error::WrongPassphraseOrDamaged);
    }

    #[test]
    fn altered_ciphertext_is_refused() {
        let mut blob = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        let result = open_with_passphrase(&blob, b"pass");
        assert_eq!(result.unwrap_err(), Error::WrongPassphraseOrDamaged);
    }

    #[test]
    fn unknown_formats_and_hostile_parameters_are_refused_before_deriving() {
        let blob = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        let mut version = blob.clone();
        version[8] = 2;
        let mut memory = blob.clone();
        memory[10..14].copy_from_slice(&(MAX_MEMORY_KIB + 1).to_be_bytes());
        let mut passes = blob.clone();
        passes[14..18].copy_from_slice(&0u32.to_be_bytes());
        for hostile in [&version, &memory, &passes, &blob[..HEADER_LEN].to_vec()] {
            assert_eq!(
                open_with_passphrase(hostile, b"pass").unwrap_err(),
                Error::MalformedSealed
            );
        }
    }

    #[test]
    fn every_seal_uses_a_fresh_salt_and_nonce() {
        let first = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        let second = seal_with(b"root key", b"pass", TEST_PARAMETERS).unwrap();
        assert_ne!(first[23..39], second[23..39]);
        assert_ne!(first[40..52], second[40..52]);
    }

    #[test]
    fn real_parameters_round_trip() {
        let blob = seal_with_passphrase(b"root key", b"correct horse").unwrap();
        assert_eq!(blob[10..14], (64 * 1024u32).to_be_bytes());
        assert_eq!(
            open_with_passphrase(&blob, b"correct horse")
                .unwrap()
                .expose(),
            b"root key"
        );
    }
}
