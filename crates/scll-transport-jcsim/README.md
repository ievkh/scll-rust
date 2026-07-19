# scll-transport-jcsim

TCP transport adapter for the **Simple Card Lifecycle Library**
([`scll`](https://crates.io/crates/scll)) targeting the Oracle Java Card
Development Kit simulator.

- `std` host crate; implements the `scll-core` `Transport` trait over a TCP
  connection to a simulator APDU bridge (e.g. `bibo+tcp://127.0.0.1:10000`).
- Blocking I/O with a per-APDU timeout owned by the transport.
- Used by the library's CI smoke tests and end-to-end examples; simulator
  deviations from GlobalPlatform behavior are documented in the design
  document (PDD §10.7) in the repository.

Most users get this crate via the `jcsim` feature of the
[`scll`](https://crates.io/crates/scll) facade.

License: MIT OR Apache-2.0.
