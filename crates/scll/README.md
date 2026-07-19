# scll

Facade crate for the **Simple Card Lifecycle Library** — off-card GlobalPlatform
card management in Rust (SCP02/SCP03 secure channels, SSD/applet lifecycle,
CAP loading, key provisioning).

Re-exports [`scll-core`](https://crates.io/crates/scll-core) plus, behind Cargo
features, the shipped backend and transports:

| Feature | Effect |
|---|---|
| `backend-rustcrypto` (default) | Pure-Rust crypto backend (`scll-backend-rustcrypto`) |
| `pcsc` | PC/SC transport (`scll-transport-pcsc`) |
| `jcsim` | Oracle Java Card simulator TCP transport (`scll-transport-jcsim`) |
| `std` | Host `critical-section` impl for the backend |

Also provides `CardManager`, an assembled transport + backend + secure-channel
handle behind ergonomic methods.

Most users depend on this crate. Constrained (`no_std`) targets depend on
`scll-core` directly and supply their own transport/backend.

Design document, examples, and full README: see the
[repository](https://github.com/ievkh/scll-rust).

License: MIT OR Apache-2.0.
