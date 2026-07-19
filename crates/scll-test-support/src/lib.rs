//! Test-only harness shared across the `scll` workspace crates.
//!
//! Unlike the `no_std` [`scll-test-util`] crate (which exposes only `HexSlice`),
//! this crate is `std` and owns its buffers, so it can hold scripted — and
//! later, recorded — APDU traces. It is pulled in only as a `dev-dependency`,
//! so it never enters any production or `no_std` build graph (Cargo does not
//! propagate `dev-dependencies` to dependents, and does not build them for a
//! normal `cargo build`). The `scll-core` → `scll-test-support` → `scll-core`
//! dev-dependency cycle this creates is permitted by Cargo.
//!
//! ## Stage 0 scope
//! This crate currently ships [`MockTransport`] only. The `replay`, `fixtures`,
//! and `refs` modules are added at the stages
//! that first use them (S3 parsers / S6 workflow replay), so that no unused
//! `todo!()` is reachable from a public path before then.
//!
//! ```
//! use scll_core::transport::Transport;
//! use scll_test_support::MockTransport;
//!
//! // Script one exchange: a SELECT C-APDU answered with `9000`.
//! let select: &[u8] = &[0x00, 0xA4, 0x04, 0x00, 0x00];
//! let mut mock = MockTransport::new(&[(select, &[0x90, 0x00])]);
//!
//! let rapdu = mock.transmit(select).unwrap();
//! assert_eq!(rapdu.as_slice(), &[0x90, 0x00]);
//! mock.assert_drained();
//! ```
//!
//! [`scll-test-util`]: https://docs.rs/scll-test-util

pub mod fixtures;
pub mod mock_transport;
pub mod replay;
pub mod stub_backend;

pub use mock_transport::MockTransport;
pub use replay::Trace;
pub use stub_backend::StubBackend;
