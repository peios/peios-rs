//! Verification of signatures made by OpenSSL, an independent implementation.
//!
//! The keys and signatures under `data/verify` were made once with the
//! OpenSSL command line over `data/verify/message`.

use peios_crypto::digest::Algorithm as Hash;
use peios_crypto::{
    Error, KeyAlgorithm, PrivateKey, Signer, VerificationAlgorithm, VerifyingKey, VerifyingKeyKind,
    MAX_RSA_MODULUS_BITS,
};

const MESSAGE: &[u8] = include_bytes!("data/verify/message");

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("data/verify/", $name)).as_slice()
    };
}

const HASHES: [(Hash, &str); 3] = [
    (Hash::Sha256, "sha256"),
    (Hash::Sha384, "sha384"),
    (Hash::Sha512, "sha512"),
];

fn ecdsa_signature(curve: &str, hash: &str) -> &'static [u8] {
    match (curve, hash) {
        ("p256", "sha256") => fixture!("p256-ecdsa-sha256.sig"),
        ("p256", "sha384") => fixture!("p256-ecdsa-sha384.sig"),
        ("p256", "sha512") => fixture!("p256-ecdsa-sha512.sig"),
        ("p384", "sha256") => fixture!("p384-ecdsa-sha256.sig"),
        ("p384", "sha384") => fixture!("p384-ecdsa-sha384.sig"),
        ("p384", "sha512") => fixture!("p384-ecdsa-sha512.sig"),
        _ => unreachable!(),
    }
}

#[test]
fn ecdsa_verifies_with_any_hash_on_either_curve() {
    let keys = [
        ("p256", fixture!("p256.spki"), VerifyingKeyKind::EcdsaP256),
        ("p384", fixture!("p384.spki"), VerifyingKeyKind::EcdsaP384),
    ];
    for (curve, spki, kind) in keys {
        let key = VerifyingKey::from_spki(spki).unwrap();
        assert_eq!(key.kind(), kind);
        for (hash, name) in HASHES {
            let signature = ecdsa_signature(curve, name);
            key.verify(VerificationAlgorithm::Ecdsa(hash), MESSAGE, signature)
                .unwrap_or_else(|error| panic!("{curve} {name}: {error}"));
            assert_eq!(
                key.verify(VerificationAlgorithm::Ecdsa(hash), b"other", signature),
                Err(Error::VerificationFailed),
            );
        }
    }
}

#[test]
fn ecdsa_signature_with_the_wrong_hash_does_not_verify() {
    let key = VerifyingKey::from_spki(fixture!("p384.spki")).unwrap();
    let made_with_sha256 = fixture!("p384-ecdsa-sha256.sig");
    let result = key.verify(
        VerificationAlgorithm::Ecdsa(Hash::Sha384),
        MESSAGE,
        made_with_sha256,
    );
    assert_eq!(result, Err(Error::VerificationFailed));
}

#[test]
fn rsa_of_an_unusual_size_verifies_pkcs1_and_pss() {
    let key = VerifyingKey::from_spki(fixture!("rsa3000.spki")).unwrap();
    assert_eq!(key.kind(), VerifyingKeyKind::Rsa { modulus_bits: 3000 });
    let signatures = [
        (
            VerificationAlgorithm::RsaPkcs1(Hash::Sha256),
            fixture!("rsa3000-pkcs1-sha256.sig"),
        ),
        (
            VerificationAlgorithm::RsaPkcs1(Hash::Sha384),
            fixture!("rsa3000-pkcs1-sha384.sig"),
        ),
        (
            VerificationAlgorithm::RsaPkcs1(Hash::Sha512),
            fixture!("rsa3000-pkcs1-sha512.sig"),
        ),
        (
            VerificationAlgorithm::RsaPss(Hash::Sha256),
            fixture!("rsa3000-pss-sha256.sig"),
        ),
        (
            VerificationAlgorithm::RsaPss(Hash::Sha384),
            fixture!("rsa3000-pss-sha384.sig"),
        ),
        (
            VerificationAlgorithm::RsaPss(Hash::Sha512),
            fixture!("rsa3000-pss-sha512.sig"),
        ),
    ];
    for (algorithm, signature) in signatures {
        key.verify(algorithm, MESSAGE, signature)
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error}"));
    }
}

#[test]
fn pss_with_a_salt_other_than_the_hash_length_does_not_verify() {
    let key = VerifyingKey::from_spki(fixture!("rsa3000.spki")).unwrap();
    let result = key.verify(
        VerificationAlgorithm::RsaPss(Hash::Sha256),
        MESSAGE,
        fixture!("rsa3000-pss-sha256-maxsalt.sig"),
    );
    assert_eq!(result, Err(Error::VerificationFailed));
}

#[test]
fn rsa_range_is_2048_to_8192_bits() {
    let largest = VerifyingKey::from_spki(fixture!("rsa8192.spki")).unwrap();
    assert_eq!(
        largest.kind(),
        VerifyingKeyKind::Rsa {
            modulus_bits: MAX_RSA_MODULUS_BITS
        }
    );
    largest
        .verify(
            VerificationAlgorithm::RsaPkcs1(Hash::Sha256),
            MESSAGE,
            fixture!("rsa8192-pkcs1-sha256.sig"),
        )
        .unwrap();
    for too_small_or_large in [fixture!("rsa1024.spki"), fixture!("rsa8704.spki")] {
        assert_eq!(
            VerifyingKey::from_spki(too_small_or_large),
            Err(Error::Unsupported)
        );
    }
}

#[test]
fn compressed_points_are_accepted_and_canonicalised() {
    let compressed = VerifyingKey::from_spki(fixture!("p256-compressed.spki")).unwrap();
    let uncompressed = VerifyingKey::from_spki(fixture!("p256.spki")).unwrap();
    assert_eq!(compressed, uncompressed);
    assert_eq!(compressed.spki(), fixture!("p256.spki"));
    compressed
        .verify(
            VerificationAlgorithm::Ecdsa(Hash::Sha256),
            MESSAGE,
            fixture!("p256-ecdsa-sha256.sig"),
        )
        .unwrap();
}

#[test]
fn algorithm_family_must_match_the_key() {
    let ec = VerifyingKey::from_spki(fixture!("p256.spki")).unwrap();
    let rsa = VerifyingKey::from_spki(fixture!("rsa3000.spki")).unwrap();
    let pkcs1 = VerificationAlgorithm::RsaPkcs1(Hash::Sha256);
    let ecdsa = VerificationAlgorithm::Ecdsa(Hash::Sha256);
    assert_eq!(
        ec.verify(pkcs1, MESSAGE, b"x"),
        Err(Error::IncompatibleScheme)
    );
    assert_eq!(
        rsa.verify(ecdsa, MESSAGE, b"x"),
        Err(Error::IncompatibleScheme)
    );
}

#[test]
fn sha1_signatures_have_no_algorithm_to_name() {
    // VerificationAlgorithm offers no SHA-1 variant, so the closest a caller
    // can get is SHA-256, which a SHA-1 signature doesn't satisfy.
    let key = VerifyingKey::from_spki(fixture!("p256.spki")).unwrap();
    let result = key.verify(
        VerificationAlgorithm::Ecdsa(Hash::Sha256),
        MESSAGE,
        fixture!("p256-ecdsa-sha1.sig"),
    );
    assert_eq!(result, Err(Error::VerificationFailed));
}

#[test]
fn bare_keys_and_garbage_are_refused() {
    let point = &fixture!("p256.spki")[fixture!("p256.spki").len() - 65..];
    for input in [point, b"not a key".as_slice(), &[]] {
        assert_eq!(VerifyingKey::from_spki(input), Err(Error::InvalidKey));
    }
}

#[test]
fn peios_public_keys_convert_and_verify_their_own_signatures() {
    let key = PrivateKey::generate(KeyAlgorithm::EcdsaP384).unwrap();
    let scheme = key.algorithm().default_signature_scheme();
    let signature = key.sign(scheme, MESSAGE).unwrap();
    let verifying = VerifyingKey::from(key.public_key());
    assert_eq!(verifying.spki(), key.public_key().spki());
    verifying
        .verify(
            VerificationAlgorithm::Ecdsa(Hash::Sha384),
            MESSAGE,
            &signature,
        )
        .unwrap();
}
