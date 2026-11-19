---
title: Using Cryptography from Rust
type: how-to
description: Generate keys, sign and verify, and protect a private key at rest with the peios-crypto crate.
---

Use the `peios-crypto` crate whenever Peios-authored Rust code needs
cryptography. It offers keys, signatures, passphrase sealing for keys at
rest, and the building blocks of random bytes, SHA-2 digests and HMAC.

The crate's choices are deliberately limited. You pick from a short list of
key types and signature schemes rather than supplying parameters, so a
weak or mismatched combination can't be expressed. Secret bytes are wiped
from memory when dropped and never appear in `Debug` output.

## Before you start

- Add `peios-crypto` from the peios-rs repository to your `Cargo.toml`.
- Handle `Error::PolicyRejected`. Peios crypto policy can refuse an
  algorithm on a particular machine. peios-crypto 0.1 doesn't enforce the
  policy and never returns this error; versions that enforce it keep the
  same API.

## Generate a key and sign

1. Generate a key with one of the `KeyAlgorithm` choices:

   ```rust
   use peios_crypto::{KeyAlgorithm, PrivateKey, Signer};

   let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256)?;
   ```

2. Sign with the key's default scheme. Each key type has one that suits
   it, so you don't need to choose a hash or padding:

   ```rust
   let scheme = key.algorithm().default_signature_scheme();
   let signature = key.sign(scheme, b"message")?;
   ```

3. Give the public key to whoever verifies, as a DER
   `SubjectPublicKeyInfo`:

   ```rust
   let spki = key.public_key().spki();
   ```

Write code that signs against the `Signer` trait rather than `PrivateKey`.
A key held in hardware implements the same trait, so the code works
unchanged when the key moves out of process memory.

## Verify a signature

Load the public key and verify with the scheme the signer used:

```rust
use peios_crypto::{PublicKey, SignatureScheme};

let public = PublicKey::from_spki(&spki)?;
public.verify(SignatureScheme::EcdsaSha256, b"message", &signature)?;
```

`PublicKey::from_spki` accepts only the canonical DER encoding of a key
type Peios offers. A bare RSA key, a raw EC point or a compressed point is
refused with `Error::InvalidKey`.

## Protect a private key at rest

Seal the key's PKCS #8 encoding under a passphrase, and store the result:

```rust
use peios_crypto::{open_with_passphrase, seal_with_passphrase};

let pkcs8 = key.to_pkcs8()?;
let sealed = seal_with_passphrase(pkcs8.expose(), passphrase.expose())?;
```

To use the key again, open the blob and load it:

```rust
let pkcs8 = open_with_passphrase(&sealed, passphrase.expose())?;
let key = PrivateKey::from_pkcs8(pkcs8.expose())?;
```

Sealing derives a key from the passphrase with Argon2id, using 64 MiB of
memory, and encrypts with AES-256-GCM. The work makes each guess of the
passphrase expensive, but it can't make a weak passphrase strong. The
crate sets no minimum, so check the passphrase's strength in your program
before sealing anything valuable, such as a certificate authority's key.

Keep passphrases in a `Secret` too, as these examples do, so that they're
wiped from memory when you're finished with them.

## Check the result

Opening a sealed blob with the wrong passphrase fails with
`Error::WrongPassphraseOrDamaged`. That error also covers a blob that was
altered or damaged, deliberately: distinguishing the two would help someone
guessing passphrases more than it helps you.

## See also

- [Using the SDK from Rust](~peios/sdk-basics/using-the-sdk-from-rust)
