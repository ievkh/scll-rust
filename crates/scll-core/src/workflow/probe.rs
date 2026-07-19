//! Step 1 — transport probe (PDD §5.1).
//!
//! Trivial wrapper over `Transport::{capabilities,is_connected}`. No card-side
//! state. `TransportUnavailable` when the transport reports it cannot be used.
//! The transport's identity is not derivable from the trait, so the caller
//! supplies it (`pcsc`/`jcsim`/`user`) for the report.

use heapless::Vec;

use crate::error::ScllError;
use crate::report::{ProbeParams, ProbeReport, TransportName};
use crate::transport::Transport;

/// Probe APDU transport availability and self-reported capabilities.
///
/// # Errors
/// Returns [`ScllError::TransportUnavailable`] if the transport reports it is
/// not connected.
pub fn probe(t: &mut dyn Transport, name: TransportName) -> Result<ProbeReport, ScllError> {
    if !t.is_connected() {
        return Err(ScllError::TransportUnavailable);
    }
    Ok(ProbeReport {
        effective: ProbeParams {
            transport_name: name,
            transport_capabilities: t.capabilities(),
        },
        warnings: Vec::new(),
    })
}
