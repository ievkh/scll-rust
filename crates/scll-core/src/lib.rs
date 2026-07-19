//! # scll-core
//!
//! Hardware- and crypto-free core of the Simple Card Lifecycle Library.
//! Holds transport/backend **traits**, `GlobalPlatform` command builders, the
//! SCP02/SCP03 state machines (state only — crypto is delegated to a backend),
//! the CAP parser, and the public model/report/error types.
//!
//! Design reference: `docs/pdd.md`. Section numbers in module docs refer
//! to that document.
//!
//! ## `no_std`
//! This crate is `no_std` and **alloc-free**: no `extern crate alloc`. Every
//! former `Vec`/`String` is a fixed-capacity `heapless` collection sized from
//! [`limits`]. `std` is enabled only under `cfg(test)` so dev-dependencies
//! (e.g. `proptest`, §10.4) and host-side tests can use it; the shipped library
//! never links `std`. Concrete transports (`scll-transport-pcsc`/`-jcsim`) are
//! separate `std` host crates and are not part of an embedded build.
//!
//! ## Testability (PDD §3.5)
//! Every byte-level transform here is a pure function with no transport and no
//! crypto dependency, so it is unit-testable and fuzzable directly.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

// --- Capacity constants for the no_std/heapless build ---
pub mod limits; // fixed buffer/collection capacities (wire-level + product caps)

// --- Public model & API surface ---
pub mod error; // §8  ScllError / WarningKind / BackendError
pub mod model; // §6  CardInfo and friends
pub mod report; // §7  per-function *Report and *Params types

// --- Primitive transforms (pure; §3.5) ---
pub mod aid; // Aid newtype (5..16 bytes, ISO/IEC 7816-5)
pub(crate) mod hexfmt; // Debug helper: render raw byte fields as hex strings
pub mod tlv; // BER-TLV parse/encode

// --- Abstractions implemented outside the core ---
pub mod backend;
pub mod transport; // §3.2 Transport trait // §3.3 split backend traits

// --- GlobalPlatform wire layer ---
pub mod cap; // §5.4a CAP-file parser (JC VM Spec v3.1 Ch. 6)
pub mod command; // §5 APDU builders (SELECT, GET DATA/STATUS, PUT KEY, DELETE, INSTALL, LOAD, SET STATUS)
pub mod lifecycle;
pub mod response; // §5.2 card-response parsers (CRD '66', CCI '67', GET STATUS 'E3', key-info '00E0')
pub mod scp; // §4.3 selection rule + §5.9 SCP02/03 state machines // §5.11 card life-cycle transition state machine

// --- High-level workflow orchestration ---
pub mod workflow; // §5 steps 1–12 (discover, keys, ssd, applet, open_scp, transmit, card_status)

/// Library version string, surfaced here instead of stamped on every report
/// (PDD §7: audit metadata belongs in a tracing span or this constant).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Spec baseline this crate targets (PDD front-matter).
pub const SPEC_BASELINE: &str = "GPCS v2.3.1; Amendment D v1.1.2 (SCP03); Amendment E v1.0.1";
