//! Behaviour of peios-crypto's public API.

use aws_lc_rs::signature::KeyPair;
use peios_crypto::{
    digest, hmac, random, Error, KeyAlgorithm, PrivateKey, PublicKey, Secret, SignatureScheme,
    Signer,
};

const ALL_ALGORITHMS: [KeyAlgorithm; 5] = [
    KeyAlgorithm::EcdsaP256,
    KeyAlgorithm::EcdsaP384,
    KeyAlgorithm::Rsa2048,
    KeyAlgorithm::Rsa3072,
    KeyAlgorithm::Rsa4096,
];

const ALL_SCHEMES: [SignatureScheme; 5] = [
    SignatureScheme::EcdsaSha256,
    SignatureScheme::EcdsaSha384,
    SignatureScheme::RsaPkcs1Sha256,
    SignatureScheme::RsaPkcs1Sha384,
    SignatureScheme::RsaPssSha256,
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_algorithm_signs_with_every_fitting_scheme() {
    for algorithm in ALL_ALGORITHMS {
        let key = PrivateKey::generate(algorithm).unwrap();
        assert_eq!(key.algorithm(), algorithm);
        for scheme in ALL_SCHEMES {
            let signed = key.sign(scheme, b"issue this");
            if !scheme.fits(algorithm) {
                assert_eq!(
                    signed.unwrap_err(),
                    Error::IncompatibleScheme,
                    "{algorithm:?} {scheme:?}"
                );
                continue;
            }
            let signature = signed.unwrap();
            let public = key.public_key();
            public.verify(scheme, b"issue this", &signature).unwrap();
            assert_eq!(
                public
                    .verify(scheme, b"issue that", &signature)
                    .unwrap_err(),
                Error::VerificationFailed,
            );
        }
    }
}

#[test]
fn ecdsa_hash_is_bound_to_the_curve() {
    assert!(SignatureScheme::EcdsaSha256.fits(KeyAlgorithm::EcdsaP256));
    assert!(!SignatureScheme::EcdsaSha384.fits(KeyAlgorithm::EcdsaP256));
    assert!(!SignatureScheme::EcdsaSha256.fits(KeyAlgorithm::EcdsaP384));
    assert!(!SignatureScheme::RsaPssSha256.fits(KeyAlgorithm::EcdsaP384));
}

#[test]
fn verification_refuses_a_scheme_that_does_not_fit() {
    let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let signature = key.sign(SignatureScheme::EcdsaSha256, b"m").unwrap();
    let result = key
        .public_key()
        .verify(SignatureScheme::RsaPkcs1Sha256, b"m", &signature);
    assert_eq!(result.unwrap_err(), Error::IncompatibleScheme);
}

#[test]
fn pkcs8_round_trips_every_algorithm() {
    for algorithm in ALL_ALGORITHMS {
        let key = PrivateKey::generate(algorithm).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();
        let loaded = PrivateKey::from_pkcs8(pkcs8.expose()).unwrap();
        assert_eq!(loaded.algorithm(), algorithm);
        assert_eq!(loaded.public_key(), key.public_key());
    }
}

#[test]
fn public_keys_round_trip_through_spki() {
    for algorithm in ALL_ALGORITHMS {
        let key = PrivateKey::generate(algorithm).unwrap();
        let public = PublicKey::from_spki(key.public_key().spki()).unwrap();
        assert_eq!(&public, key.public_key());
    }
}

#[test]
fn bare_keys_and_garbage_are_not_spki() {
    let ec = aws_lc_rs::signature::EcdsaKeyPair::generate(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
    )
    .unwrap();
    let bare_point = ec.public_key().as_ref().to_vec();
    let rsa = aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let bare_rsa = rsa.public_key().as_ref().to_vec();
    for input in [bare_point, bare_rsa, b"not a key".to_vec(), Vec::new()] {
        assert_eq!(PublicKey::from_spki(&input).unwrap_err(), Error::InvalidKey);
    }
}

#[test]
fn rsa_sizes_outside_the_menu_are_refused() {
    let rsa = aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa8192).unwrap();
    let pkcs8: aws_lc_rs::encoding::Pkcs8V1Der<'static> =
        aws_lc_rs::encoding::AsDer::as_der(&rsa).unwrap();
    assert_eq!(
        PrivateKey::from_pkcs8(pkcs8.as_ref()).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn private_keys_and_secrets_never_print_their_bytes() {
    let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let pkcs8 = key.to_pkcs8().unwrap();
    assert_eq!(format!("{pkcs8:?}"), "Secret(..)");
    assert_eq!(
        format!("{key:?}"),
        "PrivateKey { algorithm: EcdsaP256, .. }"
    );
    assert_eq!(
        format!("{:?}", Secret::from(String::from("hunter2"))),
        "Secret(..)"
    );
}

#[test]
fn sha2_matches_fips_180_examples() {
    let abc = b"abc";
    assert_eq!(
        digest::digest(digest::Algorithm::Sha256, abc),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    );
    assert_eq!(
        digest::digest(digest::Algorithm::Sha384, abc),
        hex(concat!(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed",
            "8086072ba1e7cc2358baeca134c825a7",
        )),
    );
    let mut hasher = digest::Hasher::new(digest::Algorithm::Sha512);
    hasher.update(b"a");
    hasher.update(b"bc");
    assert_eq!(
        hasher.finish(),
        hex(concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )),
    );
}

#[test]
fn hmac_matches_rfc_4231_test_case_2() {
    let key = hmac::Key::new(hmac::Algorithm::Sha256, b"Jefe");
    let data = b"what do ya want for nothing?";
    let expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    assert_eq!(hmac::sign(&key, data), expected);
    hmac::verify(&key, data, &expected).unwrap();
    let mut forged = expected.clone();
    forged[31] ^= 1;
    assert_eq!(
        hmac::verify(&key, data, &forged).unwrap_err(),
        Error::VerificationFailed
    );
}

#[test]
fn random_fills_with_distinct_bytes() {
    let mut first = [0; 32];
    let mut second = [0; 32];
    random::fill(&mut first).unwrap();
    random::fill(&mut second).unwrap();
    assert_ne!(first, second);
    assert_ne!(first, [0; 32]);
}
