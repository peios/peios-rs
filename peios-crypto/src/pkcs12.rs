//! PKCS #12 files: a private key with its certificate chain, protected by a
//! passphrase, for importing into other software.
//!
//! [`write`] produces the format OpenSSL 3 writes by default:
//!
//! - the certificates and the key are each encrypted with PBES2 (RFC 8018),
//!   using PBKDF2-HMAC-SHA256 to derive an AES-256-CBC key;
//! - the whole file is authenticated with HMAC-SHA256, keyed by the PKCS #12
//!   key derivation of RFC 7292 Appendix B with SHA-256;
//! - every derivation runs 600,000 iterations, OWASP's recommendation for
//!   PBKDF2-HMAC-SHA256.
//!
//! The key bag and the leaf certificate bag carry the same `localKeyId`,
//! the SHA-256 of the certificate, so that importers pair them. Current
//! OpenSSL, Windows 10 1709 and later, and Firefox read this format; Apple
//! systems need iOS 18 or macOS 15 or later. The legacy 3DES and SHA-1
//! format that older systems require is not offered.
//!
//! This module only encodes. Every cryptographic step runs in the backend.

use std::num::NonZeroU32;

use aws_lc_rs::cipher::{PaddedBlockEncryptingKey, UnboundCipherKey, AES_256};
use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, Tag};
use zeroize::Zeroizing;

use crate::digest::{self, Algorithm as Hash};
use crate::{hmac, random, Error, PrivateKey, Result, Signer};

const ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PFX_VERSION: u32 = 3;
const ENCRYPTED_DATA_VERSION: u32 = 0;
/// DER's SEQUENCE tag, the first byte of every certificate.
const DER_SEQUENCE: u8 = 0x30;

/// The RFC 7292 Appendix B.3 identifier for deriving a MAC key.
const KDF_MAC_ID: u8 = 3;
/// SHA-256's input block length, the `v` of RFC 7292 Appendix B.2.
const SHA256_BLOCK_LEN: usize = 64;

const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];
const OID_SHROUDED_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
const OID_CERT_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];
const OID_X509_CERTIFICATE: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];
const OID_FRIENDLY_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 20];
const OID_LOCAL_KEY_ID: &[u64] = &[1, 2, 840, 113549, 1, 9, 21];
const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
const OID_HMAC_WITH_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
const OID_AES_256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

/// Writes `key`, its `certificate` and the rest of its `chain` (issuers,
/// leaf's issuer first) as a PKCS #12 file protected by `passphrase`.
///
/// `certificate` and each `chain` entry are DER X.509 certificates.
/// `certificate` must be the key's own; a certificate that doesn't contain
/// the key's public key is refused, to catch mixed-up arguments. The
/// passphrase must not be empty; how strong it must be is the caller's
/// decision. `friendly_name` is the label importers show, if given.
pub fn write(
    key: &PrivateKey,
    certificate: &[u8],
    chain: &[&[u8]],
    friendly_name: Option<&str>,
    passphrase: &str,
) -> Result<Vec<u8>> {
    write_with(
        key,
        certificate,
        chain,
        friendly_name,
        passphrase,
        ITERATIONS,
    )
}

/// [`write`] with `iterations` for every derivation, so tests can run fast.
fn write_with(
    key: &PrivateKey,
    certificate: &[u8],
    chain: &[&[u8]],
    friendly_name: Option<&str>,
    passphrase: &str,
    iterations: u32,
) -> Result<Vec<u8>> {
    let iterations = NonZeroU32::new(iterations).ok_or(Error::InvalidInput)?;
    if passphrase.is_empty() {
        return Err(Error::InvalidInput);
    }
    for der in std::iter::once(certificate).chain(chain.iter().copied()) {
        if der.first() != Some(&DER_SEQUENCE) {
            return Err(Error::InvalidInput);
        }
    }
    let spki = key.public_key().spki();
    if !certificate.windows(spki.len()).any(|window| window == spki) {
        return Err(Error::InvalidInput);
    }

    let local_key_id = digest::digest(Hash::Sha256, certificate);
    let attributes = Attributes {
        local_key_id: &local_key_id,
        friendly_name,
    };

    let certificates = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            cert_bag(writer.next(), certificate, Some(&attributes));
            for issuer in chain {
                cert_bag(writer.next(), issuer, None);
            }
        });
    });
    let certificates = Pbes2Encrypted::new(&certificates, passphrase, iterations)?;

    let pkcs8 = key.to_pkcs8()?;
    let shrouded_key = Pbes2Encrypted::new(pkcs8.expose(), passphrase, iterations)?;
    let keys = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_SHROUDED_KEY_BAG));
                writer.next().write_tagged(Tag::context(0), |writer| {
                    writer.write_sequence(|writer| {
                        shrouded_key.write_algorithm(writer.next());
                        writer.next().write_bytes(&shrouded_key.ciphertext);
                    });
                });
                attributes.write(writer.next());
            });
        });
    });

    let authenticated_safe = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_ENCRYPTED_DATA));
                writer.next().write_tagged(Tag::context(0), |writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_u32(ENCRYPTED_DATA_VERSION);
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&oid(OID_DATA));
                            certificates.write_algorithm(writer.next());
                            writer
                                .next()
                                .write_tagged_implicit(Tag::context(0), |writer| {
                                    writer.write_bytes(&certificates.ciphertext);
                                });
                        });
                    });
                });
            });
            data_content_info(writer.next(), &keys);
        });
    });

    let mut mac_salt = [0; SALT_LEN];
    random::fill(&mut mac_salt)?;
    let mac_key = mac_key(passphrase, &mac_salt, iterations.get());
    let mac = hmac::sign(
        &hmac::Key::new(hmac::Algorithm::Sha256, &mac_key),
        &authenticated_safe,
    );

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u32(PFX_VERSION);
            data_content_info(writer.next(), &authenticated_safe);
            writer.next().write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    writer.next().write_sequence(|writer| {
                        writer.next().write_oid(&oid(OID_SHA256));
                        writer.next().write_null();
                    });
                    writer.next().write_bytes(&mac);
                });
                writer.next().write_bytes(&mac_salt);
                writer.next().write_u32(iterations.get());
            });
        });
    }))
}

fn oid(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(arcs)
}

/// A `ContentInfo` of type `data` holding `content`.
fn data_content_info(writer: DERWriter, content: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&oid(OID_DATA));
        writer
            .next()
            .write_tagged(Tag::context(0), |writer| writer.write_bytes(content));
    });
}

fn cert_bag(writer: DERWriter, certificate: &[u8], attributes: Option<&Attributes<'_>>) {
    writer.write_sequence(|writer| {
        writer.next().write_oid(&oid(OID_CERT_BAG));
        writer.next().write_tagged(Tag::context(0), |writer| {
            writer.write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_X509_CERTIFICATE));
                writer.next().write_tagged(Tag::context(0), |writer| {
                    writer.write_bytes(certificate);
                });
            });
        });
        if let Some(attributes) = attributes {
            attributes.write(writer.next());
        }
    });
}

/// The bag attributes that pair the key with its certificate.
struct Attributes<'a> {
    local_key_id: &'a [u8],
    friendly_name: Option<&'a str>,
}

impl Attributes<'_> {
    fn write(&self, writer: DERWriter) {
        writer.write_set_of(|set| {
            set.next().write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_LOCAL_KEY_ID));
                writer
                    .next()
                    .write_set_of(|values| values.next().write_bytes(self.local_key_id));
            });
            if let Some(name) = self.friendly_name {
                set.next().write_sequence(|writer| {
                    writer.next().write_oid(&oid(OID_FRIENDLY_NAME));
                    writer
                        .next()
                        .write_set_of(|values| values.next().write_bmp_string(name));
                });
            }
        });
    }
}

/// Data encrypted under PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC.
struct Pbes2Encrypted {
    salt: [u8; SALT_LEN],
    iterations: NonZeroU32,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Pbes2Encrypted {
    fn new(plaintext: &[u8], passphrase: &str, iterations: NonZeroU32) -> Result<Self> {
        let mut salt = [0; SALT_LEN];
        random::fill(&mut salt)?;
        let mut key = Zeroizing::new([0; KEY_LEN]);
        aws_lc_rs::pbkdf2::derive(
            aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt,
            passphrase.as_bytes(),
            &mut *key,
        );
        let unbound = UnboundCipherKey::new(&AES_256, &*key).map_err(|_| Error::Backend)?;
        let cipher = PaddedBlockEncryptingKey::cbc_pkcs7(unbound).map_err(|_| Error::Backend)?;
        let mut ciphertext = plaintext.to_vec();
        let context = cipher
            .encrypt(&mut ciphertext)
            .map_err(|_| Error::Backend)?;
        let iv: &[u8] = (&context).try_into().map_err(|_| Error::Backend)?;
        Ok(Self {
            salt,
            iterations,
            iv: iv.to_vec(),
            ciphertext,
        })
    }

    /// Writes the PBES2 `AlgorithmIdentifier` describing this encryption.
    fn write_algorithm(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid(OID_PBES2));
            writer.next().write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&oid(OID_PBKDF2));
                    writer.next().write_sequence(|writer| {
                        writer.next().write_bytes(&self.salt);
                        writer.next().write_u32(self.iterations.get());
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&oid(OID_HMAC_WITH_SHA256));
                            writer.next().write_null();
                        });
                    });
                });
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&oid(OID_AES_256_CBC));
                    writer.next().write_bytes(&self.iv);
                });
            });
        });
    }
}

/// The MAC key of RFC 7292 Appendix B.2, with SHA-256 and the MAC
/// identifier. The 32-byte key is exactly one SHA-256 output, so only the
/// first block `A_1` is needed and the appendix's step 6C never runs.
fn mac_key(passphrase: &str, salt: &[u8], iterations: u32) -> Zeroizing<Vec<u8>> {
    // The password is a BMPString with its terminating null character.
    let mut password = Zeroizing::new(Vec::new());
    for unit in passphrase.encode_utf16().chain(std::iter::once(0)) {
        password.extend_from_slice(&unit.to_be_bytes());
    }
    let mut hasher = digest::Hasher::new(Hash::Sha256);
    hasher.update(&[KDF_MAC_ID; SHA256_BLOCK_LEN]);
    hasher.update(&fill_blocks(salt));
    hasher.update(&fill_blocks(&password));
    let mut block = Zeroizing::new(hasher.finish());
    for _ in 1..iterations {
        *block = digest::digest(Hash::Sha256, &block);
    }
    block
}

/// `input` repeated to fill a whole number of SHA-256 blocks, as RFC 7292
/// Appendix B.2 builds `S` and `P`. An empty input stays empty.
fn fill_blocks(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let length = input.len().div_ceil(SHA256_BLOCK_LEN) * SHA256_BLOCK_LEN;
    Zeroizing::new(input.iter().copied().cycle().take(length).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    /// Known answers from OpenSSL 3's `PKCS12KDF` with SHA-256, ID 3, the
    /// password "peios" and the salt 01..10.
    #[test]
    fn mac_key_matches_openssl() {
        let salt = hex("0102030405060708090a0b0c0d0e0f10");
        let cases = [
            (
                1,
                "5304c542ec0afeb5c17dcd69bf9949110096706760ea8881e260d3c9279447db",
            ),
            (
                2048,
                "0ab1b1a4ebbe170062e2ff8be9ed927c0d863e116dfe98038a74c1eecffb9ffd",
            ),
        ];
        for (iterations, expected) in cases {
            assert_eq!(
                *mac_key("peios", &salt, iterations),
                hex(expected),
                "{iterations}"
            );
        }
    }

    use aws_lc_rs::cipher::{DecryptionContext, PaddedBlockDecryptingKey};
    use yasna::{ASN1Result, BERReader};

    use crate::KeyAlgorithm;

    const PASSPHRASE: &str = "pässwörd🔑";

    /// Stands in for a certificate: a DER SEQUENCE holding the key's SPKI,
    /// which is all `write` inspects. OpenSSL has checked real ones.
    fn fake_certificate(key: &PrivateKey) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| writer.next().write_der(key.public_key().spki()));
        })
    }

    struct Pfx {
        version: u32,
        authenticated_safe: Vec<u8>,
        mac: Vec<u8>,
        mac_salt: Vec<u8>,
        mac_iterations: u32,
    }

    fn parse_pfx(der: &[u8]) -> Pfx {
        yasna::parse_der(der, |reader| {
            reader.read_sequence(|reader| {
                let version = reader.next().read_u32()?;
                let authenticated_safe = read_data_content_info(reader.next())?;
                let (mac, mac_salt, mac_iterations) = reader.next().read_sequence(|reader| {
                    let mac = reader.next().read_sequence(|reader| {
                        reader.next().read_sequence(|reader| {
                            assert_eq!(reader.next().read_oid()?, oid(OID_SHA256));
                            reader.next().read_null()
                        })?;
                        reader.next().read_bytes()
                    })?;
                    Ok((mac, reader.next().read_bytes()?, reader.next().read_u32()?))
                })?;
                Ok(Pfx {
                    version,
                    authenticated_safe,
                    mac,
                    mac_salt,
                    mac_iterations,
                })
            })
        })
        .unwrap()
    }

    fn read_data_content_info(reader: BERReader<'_, '_>) -> ASN1Result<Vec<u8>> {
        reader.read_sequence(|reader| {
            assert_eq!(reader.next().read_oid()?, oid(OID_DATA));
            reader
                .next()
                .read_tagged(Tag::context(0), |reader| reader.read_bytes())
        })
    }

    /// Reads a PBES2 `AlgorithmIdentifier` and decrypts `ciphertext` with it.
    fn read_pbes2_and_decrypt(reader: BERReader<'_, '_>, ciphertext: &[u8]) -> ASN1Result<Vec<u8>> {
        let (salt, iterations, iv) = reader.read_sequence(|reader| {
            assert_eq!(reader.next().read_oid()?, oid(OID_PBES2));
            reader.next().read_sequence(|reader| {
                let (salt, iterations) = reader.next().read_sequence(|reader| {
                    assert_eq!(reader.next().read_oid()?, oid(OID_PBKDF2));
                    reader.next().read_sequence(|reader| {
                        let salt = reader.next().read_bytes()?;
                        let iterations = reader.next().read_u32()?;
                        reader.next().read_sequence(|reader| {
                            assert_eq!(reader.next().read_oid()?, oid(OID_HMAC_WITH_SHA256));
                            reader.next().read_null()
                        })?;
                        Ok((salt, iterations))
                    })
                })?;
                let iv = reader.next().read_sequence(|reader| {
                    assert_eq!(reader.next().read_oid()?, oid(OID_AES_256_CBC));
                    reader.next().read_bytes()
                })?;
                Ok((salt, iterations, iv))
            })
        })?;
        let mut key = [0; KEY_LEN];
        aws_lc_rs::pbkdf2::derive(
            aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iterations).unwrap(),
            &salt,
            PASSPHRASE.as_bytes(),
            &mut key,
        );
        let cipher =
            PaddedBlockDecryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, &key).unwrap())
                .unwrap();
        let mut buffer = ciphertext.to_vec();
        let iv: [u8; 16] = iv.try_into().unwrap();
        let plaintext = cipher
            .decrypt(&mut buffer, DecryptionContext::Iv128(iv.into()))
            .unwrap();
        Ok(plaintext.to_vec())
    }

    #[test]
    fn written_file_authenticates_and_holds_the_key_and_chain() {
        let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let leaf = fake_certificate(&key);
        let issuer = fake_certificate(&PrivateKey::generate(KeyAlgorithm::EcdsaP384).unwrap());
        let der = write_with(&key, &leaf, &[&issuer], Some("Jack"), PASSPHRASE, 1000).unwrap();

        let pfx = parse_pfx(&der);
        assert_eq!(pfx.version, PFX_VERSION);
        assert_eq!(pfx.mac_iterations, 1000);
        let mac_key = mac_key(PASSPHRASE, &pfx.mac_salt, pfx.mac_iterations);
        let mac_key = hmac::Key::new(hmac::Algorithm::Sha256, &mac_key);
        hmac::verify(&mac_key, &pfx.authenticated_safe, &pfx.mac).unwrap();

        let (certificates, key_bag) = yasna::parse_der(&pfx.authenticated_safe, |reader| {
            reader.read_sequence(|reader| {
                let certificates = reader.next().read_sequence(|reader| {
                    assert_eq!(reader.next().read_oid()?, oid(OID_ENCRYPTED_DATA));
                    reader.next().read_tagged(Tag::context(0), |reader| {
                        reader.read_sequence(|reader| {
                            assert_eq!(reader.next().read_u32()?, ENCRYPTED_DATA_VERSION);
                            reader.next().read_sequence(|reader| {
                                assert_eq!(reader.next().read_oid()?, oid(OID_DATA));
                                let algorithm = reader.next().read_der()?;
                                let ciphertext = reader
                                    .next()
                                    .read_tagged_implicit(Tag::context(0), |reader| {
                                        reader.read_bytes()
                                    })?;
                                yasna::parse_der(&algorithm, |reader| {
                                    read_pbes2_and_decrypt(reader, &ciphertext)
                                })
                            })
                        })
                    })
                })?;
                Ok((certificates, read_data_content_info(reader.next())?))
            })
        })
        .unwrap();

        let mut bag_count = 0;
        yasna::parse_der(&certificates, |reader| {
            reader.read_sequence_of(|reader| {
                reader.read_der()?;
                bag_count += 1;
                Ok(())
            })
        })
        .unwrap();
        assert_eq!(bag_count, 2);

        let pkcs8 = yasna::parse_der(&key_bag, |reader| {
            reader.read_sequence(|reader| {
                reader.next().read_sequence(|reader| {
                    assert_eq!(reader.next().read_oid()?, oid(OID_SHROUDED_KEY_BAG));
                    let pkcs8 = reader.next().read_tagged(Tag::context(0), |reader| {
                        reader.read_sequence(|reader| {
                            let algorithm = reader.next().read_der()?;
                            let ciphertext = reader.next().read_bytes()?;
                            yasna::parse_der(&algorithm, |reader| {
                                read_pbes2_and_decrypt(reader, &ciphertext)
                            })
                        })
                    })?;
                    reader.next().read_der()?;
                    Ok(pkcs8)
                })
            })
        })
        .unwrap();
        assert_eq!(pkcs8, key.to_pkcs8().unwrap().expose());
    }

    #[test]
    fn real_files_use_600000_iterations() {
        let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let der = write(&key, &fake_certificate(&key), &[], None, PASSPHRASE).unwrap();
        assert_eq!(parse_pfx(&der).mac_iterations, ITERATIONS);
    }

    #[test]
    fn mistakes_are_refused() {
        let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let other = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let leaf = fake_certificate(&key);
        let refused = [
            write_with(&key, &leaf, &[], None, "", 1000),
            write_with(&key, &fake_certificate(&other), &[], None, PASSPHRASE, 1000),
            write_with(&key, b"not DER", &[], None, PASSPHRASE, 1000),
            write_with(&key, &leaf, &[b"not DER"], None, PASSPHRASE, 1000),
            write_with(&key, &leaf, &[], None, PASSPHRASE, 0),
        ];
        for result in refused {
            assert_eq!(result.unwrap_err(), Error::InvalidInput);
        }
    }

    #[test]
    fn blocks_are_filled_by_repetition() {
        assert_eq!(fill_blocks(&[1, 2, 3]).len(), SHA256_BLOCK_LEN);
        assert_eq!(&fill_blocks(&[1, 2, 3])[..7], &[1, 2, 3, 1, 2, 3, 1]);
        assert_eq!(fill_blocks(&[7; 65]).len(), 2 * SHA256_BLOCK_LEN);
        assert!(fill_blocks(&[]).is_empty());
    }
}
