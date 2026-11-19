# peios-rs

Rust bindings to the public libpeios C ABI. `peios-sys` exposes raw bindings; `peios` provides owned handles and checked results.

`peios-crypto` is Peios cryptography for Rust: keys, signatures, passphrase
sealing, random bytes, digests and HMAC. Until libpeios-crypto exists it
calls aws-lc-rs directly and does not enforce Peios crypto policy; it will
move onto libpeios-crypto's C ABI without changing its API.

- [Building and testing](docs/building.md)
- [Developer documentation](docs/learn/)
- [Style and review scope](docs/style.md)
- [Historical records](docs/archive/)

pekit builds and tests the maintained sources against the Peios SDK, which
it builds from the SDK's own files. Go modules and Cargo remain supported
for SDK consumers.
