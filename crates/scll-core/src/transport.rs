//! Transport abstraction — PDD §3.2.
//!
//! Blocking; per-APDU timeout owned by the transport. The caller owns the
//! transport; the library borrows `&mut dyn Transport`. Reader enumeration is
//! the transport's responsibility. Concrete adapters live in
//! `scll-transport-pcsc` and `scll-transport-jcsim`.
//!
//! `no_std`: the trait is alloc-free even though the concrete PCSC/jcsim
//! adapters are `std` host crates — they fill these bounded `heapless` buffers.
//! `transmit` returns one short R-APDU (≤ `RAPDU_MAX`); `reset` returns ATR/ATS
//! bytes (≤ `ATR_ATS_MAX`).

use heapless::{String, Vec};

use crate::limits::{ATR_ATS_MAX, OTHER_DETAIL_MAX, RAPDU_MAX};

/// One short C-APDU in, one R-APDU out, plus capability/reset/liveness queries.
pub trait Transport {
    /// Send one short C-APDU, get one R-APDU. Per-call timeout enforced inside.
    ///
    /// # Errors
    /// Returns a [`TransportError`] if the exchange fails — e.g.
    /// [`TransportError::Timeout`], [`TransportError::CardRemoved`],
    /// [`TransportError::ReaderGone`] or [`TransportError::ProtocolError`].
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, TransportError>;

    /// Report transport capabilities (T=0 GET RESPONSE handling, protocol, contactless).
    fn capabilities(&self) -> TransportCaps;

    /// Cold/warm reset; return ATR (contact) or ATS (contactless).
    ///
    /// # Errors
    /// Returns a [`TransportError`] if the card cannot be reset — e.g.
    /// [`TransportError::ReaderGone`] or [`TransportError::ProtocolError`].
    fn reset(&mut self) -> Result<AtrAts, TransportError>;

    /// Currently negotiated protocol.
    fn protocol(&self) -> TransportProtocol;

    /// Liveness check without sending an APDU.
    fn is_connected(&self) -> bool;
}

/// Transport-level failure taxonomy (PDD §3.2, minimum set).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TransportError {
    CardRemoved,
    ReaderGone,
    Timeout,
    ProtocolError,
    Other(String<OTHER_DETAIL_MAX>),
}

/// Self-reported transport capabilities.
#[derive(Debug, Clone)]
pub struct TransportCaps {
    pub handles_t0_get_response: bool,
    pub protocol: TransportProtocol,
    pub contactless: bool,
}

/// Negotiated card protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    T0,
    T1,
    TCl,
}

/// Answer-To-Reset (contact) or Answer-To-Select (contactless) bytes.
#[derive(Debug, Clone)]
pub struct AtrAts {
    pub bytes: Vec<u8, ATR_ATS_MAX>,
    pub protocol: TransportProtocol,
}
