//! Step 10 — applet APDU exchange (PDD §5.10).
//!
//! Public wrapper over the session wrap/transmit/unwrap of step 9. Returns the
//! plaintext R-APDU data and the SW. The session's fixed security level governs
//! C-MAC / C-ENC / R-MAC (§4.1); a wrap/unwrap failure tears the session down
//! backend-side (Fork F3) and surfaces as [`ScllError::Backend`].

use heapless::Vec;

use crate::backend::{Scp02Backend, Scp03Backend};
use crate::error::ScllError;
use crate::report::{AppletTransmitParams, AppletTransmitReport};
use crate::scp::ScpSession;
use crate::transport::Transport;
use crate::workflow::session;

/// Exchange one application-level APDU over an open [`ScpSession`].
///
/// # Errors
/// Returns [`ScllError::Backend`] on a wrap/unwrap failure, a mapped transport
/// error, or [`ScllError::Card`] for a malformed response. The returned SW is
/// **not** itself treated as an error — the caller inspects `report.sw`.
pub fn transmit<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    plaintext_capdu: &[u8],
) -> Result<AppletTransmitReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let session_id = session.session_id();
    let sec_level = session.security_level();
    let scp_protocol = session.protocol();

    let (data, sw) = session::transmit_in_session(t, backend, session, plaintext_capdu)?;

    let capdu_plaintext_len = u16::try_from(plaintext_capdu.len()).unwrap_or(u16::MAX);
    let rapdu_plaintext_len = u16::try_from(data.len()).unwrap_or(u16::MAX);

    Ok(AppletTransmitReport {
        rapdu: data,
        sw,
        effective: AppletTransmitParams {
            session_id,
            capdu_plaintext_len,
            rapdu_plaintext_len,
            sw: sw.to_be_bytes(),
            sec_level,
            scp_protocol,
        },
        warnings: Vec::new(),
    })
}
