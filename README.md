# peios-rs

Rust bindings to the public libpeios C ABI. `peios-sys` exposes raw bindings; `peios` provides owned handles and checked results.

- [Building and testing](docs/building.md)
- [Developer documentation](docs/learn/)
- [Style and review scope](docs/style.md)
- [Historical records](docs/archive/)

pekit builds and tests the maintained sources against the Peios SDK, which
it builds from the SDK's own files. Go modules and Cargo remain supported
for SDK consumers.
