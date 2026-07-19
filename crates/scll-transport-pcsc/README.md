# scll-transport-pcsc

PC/SC transport adapter for the **Simple Card Lifecycle Library**
([`scll`](https://crates.io/crates/scll)). Implements the `scll-core`
`Transport` trait over the [`pcsc`](https://crates.io/crates/pcsc) crate for
real smart card readers.

- `std` host crate (Linux is the primary target; links `libpcsclite`).
- Blocking I/O with a per-APDU timeout owned by the transport; reader
  enumeration and selection included.
- Verified end-to-end against NXP JCOP 4 P71 (J3R150) with an Identiv
  uTrust 3700 F reader.

Most users get this crate via the `pcsc` feature of the
[`scll`](https://crates.io/crates/scll) facade.

License: MIT OR Apache-2.0.
