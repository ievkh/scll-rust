//! # scll — facade crate
//!
//! Re-exports `scll-core` and, behind Cargo features, the shipped backend and
//! transports (PDD §3.1). Most users depend on this crate; constrained targets
//! depend on `scll-core` directly and supply their own transport/backend.
//!
//! Features: `backend-rustcrypto` (default), `pcsc`, `jcsim`, `std`.
//!
//! ## Constructing the backend
//! `RustCryptoBackend<R>` is generic over an injected `R: RngCore + CryptoRng`
//! (Fork B) and uses a `critical-section` mutex internally. On a host, enable
//! the `std` feature (registers a `critical-section` impl) and pass an OS RNG;
//! on embedded, select a `critical-section` impl via your HAL and pass a board
//! TRNG. There is no zero-arg constructor — an RNG must be supplied.

//! ## Assembled manager
//! [`CardManager`] bundles a transport + backend (+ the open secure channel)
//! behind ergonomic methods, so callers do not thread `&mut dyn Transport`,
//! `&backend`, and `&mut ScpSession` through every step (PDD §3.6
//! §S7). It delegates to the [`scll_core::workflow`] free functions, which
//! remain available for advanced/constrained use.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub use scll_core::*;

mod manager;
pub use manager::CardManager;

#[cfg(feature = "backend-rustcrypto")]
pub use scll_backend_rustcrypto as backend_rustcrypto;

#[cfg(feature = "pcsc")]
pub use scll_transport_pcsc as transport_pcsc;

#[cfg(feature = "jcsim")]
pub use scll_transport_jcsim as transport_jcsim;
