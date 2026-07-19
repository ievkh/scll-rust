//! Step 9 — `open_scp` (PDD §5.9).
//!
//! Negotiates SCP version per §4.3 (SCP03 preferred) over the card's advertised
//! variants, SELECTs the target, runs INITIALIZE UPDATE → `scp::begin` →
//! EXTERNAL AUTHENTICATE, and yields the open [`ScpSession`] inside the report.
//! Hard-fails on EXTERNAL AUTHENTICATE rejection (no retry). For direct SD
//! targeting SELECT targets the SD; cooperative-applet routing (the applet
//! forwards IU/EA to its SD) is requested via [`ScpTargetKind::ApplicationAid`].

use heapless::Vec;

use crate::aid::Aid;
use crate::backend::{KeyBackend, KeyHandle, Scp02Backend, Scp03Backend, ScpMode};
use crate::error::ScllError;
use crate::limits::SCP03_S16_MAX;
use crate::model::ScpVariant;
use crate::report::{OpenScpParams, OpenScpReport, ScpTargetKind};
use crate::scp::{self, scp02, scp03, ScpSession};
use crate::transport::Transport;
use crate::workflow::session::{self, SW_OK};

/// SCP02 INITIALIZE UPDATE key identifier (P2). `0x00` selects the keyset's
/// default key set version (PDD §5.9 SCP02 step 4).
const SCP02_KEY_ID: u8 = 0x00;

/// The three static SD keys (ENC/MAC/DEK) as opaque backend handles. Bytes
/// never cross this boundary (§3.6).
#[derive(Debug, Clone, Copy)]
pub struct SdKeys {
    pub enc: KeyHandle,
    pub mac: KeyHandle,
    pub dek: KeyHandle,
}

/// Inputs to [`open_scp`]. `advertised` is the card's SCP list (from
/// `discover_card`); `force_scp` overrides the §4.3 selection (not
/// recommended). `kvn = 0x00` lets the card pick; `requested_level` is the
/// security level to request (capped to the card's `i`, §5.9 step 8).
pub struct OpenScpArgs<'a> {
    pub target_aid: &'a [u8],
    pub target_kind: ScpTargetKind,
    pub sd_keys: SdKeys,
    pub advertised: &'a [ScpVariant],
    pub force_scp: Option<ScpVariant>,
    pub kvn: u8,
    pub requested_level: u8,
}

/// Open an SCP03/SCP02 secure channel; the [`OpenScpReport`] carries the
/// session as its payload.
///
/// # Errors
/// [`ScllError::ScpProtocolUnsupported`] if no supported variant is available,
/// [`ScllError::CardCryptogramFail`] if the card cryptogram does not verify,
/// [`ScllError::ExternalAuthFail`] if EXTERNAL AUTHENTICATE is rejected, or a
/// transport / backend / [`ScllError::Card`] error.
#[allow(clippy::similar_names)] // iu_capdu / iu_data are the IU command vs response
pub fn open_scp<B>(
    t: &mut dyn Transport,
    backend: &B,
    args: &OpenScpArgs<'_>,
) -> Result<OpenScpReport, ScllError>
where
    B: KeyBackend + Scp02Backend + Scp03Backend,
{
    let variant =
        scp::select(args.advertised, args.force_scp).ok_or(ScllError::ScpProtocolUnsupported)?;

    // SELECT the target (SD for direct targeting; applet for cooperative routing).
    let fci = session::select(t, args.target_aid)?;

    // §6.2.2.1: the card derives the pseudo-random card challenge over the
    // application's *full* registered AID. A caller may SELECT with a partial
    // (RID-only / truncated) AID, which would make the recomputed challenge —
    // and thus the defence-in-depth check in `scp03::begin` — fail spuriously.
    // Prefer the DF name (tag `'84'`) the card echoes in the FCI `6F` template
    // (GPCS v2.3.1 §11.1.4 / ISO/IEC 7816-4 §7.4.3.3); fall back to the SELECT
    // target only when the FCI omits it or is not a valid AID. A malformed FCI
    // is best-effort: it degrades to the fallback rather than aborting the open.
    let target_aid = Aid::new(args.target_aid)?;
    let invoker_aid = session::fci_df_name(&fci)
        .ok()
        .flatten()
        .and_then(|name| Aid::new(name).ok())
        .unwrap_or_else(|| target_aid.clone());

    let (session, kvn_effective, i_param_effective, security_level_effective) = match variant {
        ScpVariant::Scp03 { i_param } => {
            // Mode (S8/S16) fixes the host-challenge length (8 or 16 bytes).
            let mode = ScpMode::from_i(i_param);
            let mut host_buf = [0u8; SCP03_S16_MAX];
            let host_len = mode.field_len();
            backend.random_bytes(&mut host_buf[..host_len])?;
            let host_challenge = &host_buf[..host_len];

            let iu_capdu = scp03::iu_command(args.kvn, host_challenge)?;
            let (iu_data, sw) = session::transmit_plain(t, &iu_capdu)?;
            if sw != SW_OK {
                return Err(ScllError::from_general_sw(sw));
            }
            let iu = scp03::parse_iu_response(&iu_data)?;
            let (state, ea) = scp03::begin(
                backend,
                &args.sd_keys.enc,
                &args.sd_keys.mac,
                args.kvn,
                args.requested_level,
                host_challenge,
                invoker_aid.as_bytes(), // full AID (FCI tag '84') for the §6.2.2.1 check
                &iu_data,
            )?;
            let level = state.security_level();
            let (_d, ea_sw) = session::transmit_plain(t, &ea)?;
            if ea_sw != SW_OK {
                return Err(ScllError::ExternalAuthFail { sw: ea_sw });
            }
            (ScpSession::Scp03(state), iu.kvn, iu.i_param, level)
        }
        ScpVariant::Scp02 { i_param } => {
            // SCP02 always uses an 8-byte host challenge (GPCS §E).
            let mut host_challenge = [0u8; 8];
            backend.random_bytes(&mut host_challenge)?;
            let iu_capdu = scp02::iu_command(args.kvn, SCP02_KEY_ID, &host_challenge)?;
            let (iu_data, sw) = session::transmit_plain(t, &iu_capdu)?;
            if sw != SW_OK {
                return Err(ScllError::from_general_sw(sw));
            }
            let iu = scp02::parse_iu_response(&iu_data)?;
            let (state, ea) = scp02::begin(
                backend,
                &args.sd_keys.enc,
                &args.sd_keys.mac,
                &args.sd_keys.dek,
                i_param,
                args.kvn,
                args.requested_level,
                &host_challenge,
                &iu_data,
            )?;
            let level = state.security_level();
            let (_d, ea_sw) = session::transmit_plain(t, &ea)?;
            if ea_sw != SW_OK {
                return Err(ScllError::ExternalAuthFail { sw: ea_sw });
            }
            (ScpSession::Scp02(state), iu.kvn, i_param, level)
        }
    };

    let session_id = session.session_id();
    let scp_protocol_effective = session.protocol();

    Ok(OpenScpReport {
        session,
        effective: OpenScpParams {
            target_aid: target_aid.clone(),
            target_kind: args.target_kind,
            sd_aid_used_for_keys: target_aid,
            scp_protocol_effective,
            kvn_requested: args.kvn,
            kvn_effective,
            i_param_effective,
            security_level_requested: args.requested_level,
            security_level_effective,
            session_id,
            invoker_aid_used: invoker_aid,
        },
        warnings: Vec::new(),
    })
}
