//! Steps 3 & 6 — PUT KEY / DELETE KEY engine (PDD §5.3/§5.6).
//!
//! One public pair since patch #31: [`put_sd_keys`] and [`delete_sd_keyset`],
//! parameterised by `target_sd_aid` (ISD for §5.3, SSD for §5.6) — the former
//! per-SD wrapper pairs were pure aliases and were collapsed. The engine is
//! **Add-only over a session opened against the target SD itself** (PUT KEY
//! P1 = `0x00`, GPCS v2.3.1 §11.8.2.3 Table 11-66): the in-place
//! Replace/Generate paths and the parent-mediated `INSTALL [for
//! Personalization]` mechanism were removed in patch #29 as unverified or
//! failing on every available target (NXP JCOP 4 P71, jcsim). Key bytes never
//! cross the API: new keys are [`KeyHandle`]s, encrypted under the DEK by the
//! backend (SCP03 static DEK / SCP02 session DEK, chosen by protocol — see
//! [`encrypt`]).
//!
//! The card echoes `new_kvn ‖ KCV_ENC ‖ KCV_MAC ‖ KCV_DEK`; the engine compares
//! it against the locally computed KCVs and fails closed on a mismatch
//! ([`ScllError::KeyCheckValueMismatch`], GPCS v2.3.1 §11.8.3.1).
//!
//! DELETE KEY is KVN-only (a single `'D2'` reference, GPCS v2.3.1
//! §11.2.2.3.2): GP cards (e.g. JCOP) address a PUT KEY key set as a unit by
//! its key version, and per-KID deletion of such a set returns `6A88`. The
//! active-/last-keyset guards need the registry snapshot that fast discovery
//! skips; the card's status word is authoritative.

use heapless::Vec;

use crate::aid::Aid;
use crate::backend::{KeyBackend, KeyHandle, KeyKind, Scp02Backend, Scp03Backend};
use crate::command::delete::delete_key;
use crate::command::put_key::{put_key, KeyBlock};
use crate::error::ScllError;
use crate::limits::ENC_KEY_BLOCK_MAX;
use crate::model::KeyType;
use crate::report::{DeleteKeyParams, DeleteKeyReport, PutKeysParams, PutKeysReport, ScpProtocol};
use crate::scp::ScpSession;
use crate::transport::Transport;
use crate::workflow::session::{self, SW_OK, SW_REF_NOT_FOUND};

/// PUT KEY key-block type byte: AES (SCP03) vs 3DES (SCP02), GPCS v2.3.1 §11.8.
const KEY_TYPE_AES: u8 = 0x88;
const KEY_TYPE_3DES: u8 = 0x80;
/// PUT KEY P1 = `0x00`: Add — the new KVN travels inside the data field
/// (GPCS v2.3.1 §11.8.2.1, Table 11-66).
const P1_ADD: u8 = 0x00;
/// Echoed KCV response: `new_kvn ‖ 3×KCV(3)` = 10 bytes (GPCS §11.8.3.1).
const KCV_ECHO_LEN: usize = 1 + 9;

/// Three new SCP keys (ENC/MAC/DEK) as opaque handles (from `import`/`generate`)
/// plus their shared algorithm/length. All three keys must be the same `kind`,
/// and the kind must match the negotiated SCP (AES for SCP03, two-key 3DES for
/// SCP02); the `kind` drives the AES clear-key-length byte (Amendment D §7.2),
/// so AES-192 and AES-256 are written correctly.
#[derive(Debug, Clone, Copy)]
pub struct NewKeyset {
    pub enc: KeyHandle,
    pub mac: KeyHandle,
    pub dek: KeyHandle,
    pub kind: KeyKind,
}

/// Inputs to [`put_sd_keys`]. `target_sd_aid` selects the SD (ISD or SSD);
/// the session must have been opened against that SD itself with its current
/// keys. `dek` is the DEK handle the backend uses to encrypt the new keys
/// under SCP03 (always the static DEK of the keyset the channel authenticated
/// with, Amendment D §6.2.6). Under SCP02 it is **ignored** — the engine uses
/// the session's own derived DEK instead (GPCS v2.3.1 §E.4.1; see
/// [`crate::backend::Scp02Backend::scp02_encrypt_put_key_payload_for_session`]).
/// Confirmed empirically against a live NXP JCOP 4 P71: PUT KEY encrypted
/// under the static/base DEK over a direct SCP02 channel is rejected (`6982`);
/// under the session DEK it succeeds.
pub struct PutSdKeysArgs<'a> {
    pub dek: KeyHandle,
    pub new_keys: NewKeyset,
    pub new_kvn: u8,
    pub target_sd_aid: &'a [u8],
}

/// §5.3/§5.6 — add a keyset on a Security Domain (PUT KEY P1 = `0x00`) over a
/// session opened against that SD with its current keys. Rotation is
/// Add-then-delete: add the new KVN, re-open on it, then remove the superseded
/// version via [`delete_sd_keyset`]. On the validated targets a fresh SSD
/// authenticates with the keyset it inherits from its parent, so first keying
/// and rotation use this same path (§5.6).
///
/// # Errors
/// [`ScllError::KeyCheckValueMismatch`] on a KCV echo mismatch, a backend error,
/// or a transport / [`ScllError::Card`] error.
#[allow(clippy::similar_names)] // kcv_enc / kcv_mac / kcv_dek are the GP key names
pub fn put_sd_keys<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    args: &PutSdKeysArgs<'_>,
) -> Result<PutKeysReport, ScllError>
where
    B: KeyBackend + Scp02Backend + Scp03Backend,
{
    let keyset = args.new_keys;
    let is_scp03 = matches!(session.protocol(), ScpProtocol::Scp03);
    let key_type_byte = if is_scp03 {
        KEY_TYPE_AES
    } else {
        KEY_TYPE_3DES
    };
    let report_key_type = if is_scp03 { KeyType::Aes } else { KeyType::Des };

    // Encrypt each new key under the protocol-appropriate DEK (see `encrypt`).
    let enc_blob = encrypt(backend, session, args.dek, keyset.enc)?;
    let mac_blob = encrypt(backend, session, args.dek, keyset.mac)?;
    let dek_blob = encrypt(backend, session, args.dek, keyset.dek)?;
    let kcv_enc = backend.compute_kcv(&keyset.enc)?;
    let kcv_mac = backend.compute_kcv(&keyset.mac)?;
    let kcv_dek = backend.compute_kcv(&keyset.dek)?;

    // Plaintext key length for the AES clear-key-length byte (Amendment D §7.2)
    // and the report. AES-192 differs from its 32-byte ciphertext; SCP02's
    // two-key 3DES is always 16 and carries no inner length byte.
    let clear_len = if is_scp03 {
        u8::try_from(keyset.kind.clear_len()).unwrap_or(16)
    } else {
        16
    };

    let blocks = [
        key_block(key_type_byte, enc_blob.as_slice(), kcv_enc, clear_len),
        key_block(key_type_byte, mac_blob.as_slice(), kcv_mac, clear_len),
        key_block(key_type_byte, dek_blob.as_slice(), kcv_dek, clear_len),
    ];

    let capdu = put_key(P1_ADD, args.new_kvn, &blocks)?;
    let (echo, sw) = session::transmit_in_session(t, backend, session, &capdu)?;
    if sw != SW_OK {
        return Err(ScllError::from_general_sw(sw));
    }

    // Verify the KCV echo (when the card returns the full 10-byte form).
    let kcvs = verify_kcv_echo(&echo, args.new_kvn, kcv_enc, kcv_mac, kcv_dek)?;

    Ok(PutKeysReport {
        effective: PutKeysParams {
            target_sd_aid: Aid::new(args.target_sd_aid)?,
            scp_protocol: session.protocol(),
            new_kvn: args.new_kvn,
            key_type: report_key_type,
            key_length: clear_len,
            kcvs,
        },
        warnings: Vec::new(),
    })
}

/// §5.3.3/§5.6 — delete an entire key **version** (all keys at `kvn`) from a
/// Security Domain with a single DELETE carrying only the `'D2'` (KVN)
/// reference (GPCS v2.3.1 §11.2.2.3.2: omitting `'D0'` selects every key of
/// that version). GP cards (e.g. JCOP) address a PUT KEY key set as a unit by
/// its key version. The session must have been opened against `target_sd_aid`
/// itself. The caller must not target the keyset the current session
/// authenticated with, nor the card's last remaining ISD keyset — the card's
/// SW decides, but either would strand the SD. Note the JCOP 4 P71 empirical
/// limit (PDD §12): `DELETE [key]` on an SSD's **own** channel returns `6985`
/// under all tested conditions — the ISD-level object DELETE of the SSD
/// removes its key material instead.
///
/// # Errors
/// [`ScllError::KeyNotFound`] if the key version is absent (`6A88`), or a
/// transport / backend / [`ScllError::Card`] error.
pub fn delete_sd_keyset<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    kvn: u8,
    target_sd_aid: &[u8],
) -> Result<DeleteKeyReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let capdu = delete_key(None, Some(kvn))?;
    let (_data, sw) = session::transmit_in_session(t, backend, session, &capdu)?;
    match sw {
        SW_OK => {}
        SW_REF_NOT_FOUND => return Err(ScllError::KeyNotFound),
        other => return Err(ScllError::from_general_sw(other)),
    }
    Ok(DeleteKeyReport {
        effective: DeleteKeyParams {
            target_sd_aid: Aid::new(target_sd_aid)?,
            kvn,
        },
        warnings: Vec::new(),
    })
}

/// Assemble one PUT KEY `KeyBlock` (borrows the ciphertext; no alloc).
fn key_block(key_type: u8, encrypted_key: &[u8], kcv: [u8; 3], clear_key_len: u8) -> KeyBlock<'_> {
    KeyBlock {
        key_type,
        encrypted_key,
        kcv,
        clear_key_len,
    }
}

/// Concatenate the three KCVs and, when the card returned the full
/// `new_kvn ‖ 3×KCV` echo, verify it matches (GPCS v2.3.1 §11.8.3.1).
#[allow(clippy::similar_names)] // kcv_enc / kcv_mac / kcv_dek are the GP key names
fn verify_kcv_echo(
    echo: &[u8],
    new_kvn: u8,
    kcv_enc: [u8; 3],
    kcv_mac: [u8; 3],
    kcv_dek: [u8; 3],
) -> Result<[u8; 9], ScllError> {
    let mut kcvs = [0u8; 9];
    kcvs[0..3].copy_from_slice(&kcv_enc);
    kcvs[3..6].copy_from_slice(&kcv_mac);
    kcvs[6..9].copy_from_slice(&kcv_dek);
    if echo.len() >= KCV_ECHO_LEN {
        let mut expected = [0u8; KCV_ECHO_LEN];
        expected[0] = new_kvn;
        expected[1..].copy_from_slice(&kcvs);
        if echo[..KCV_ECHO_LEN] != expected {
            return Err(ScllError::KeyCheckValueMismatch);
        }
    }
    Ok(kcvs)
}

/// Encrypt `new` for the negotiated protocol's PUT KEY payload.
///
/// SCP03 uses the caller-supplied `dek` (the static DEK, Amendment D §6.2.6 —
/// SCP03 has no session DEK). SCP02 uses the open session's own derived DEK
/// via [`Scp02Backend::scp02_encrypt_put_key_payload_for_session`] (GPCS
/// v2.3.1 §E.4.1): PUT KEY over a direct SCP02 channel encrypted under the
/// static base DEK is rejected (`6982` on a live NXP JCOP 4 P71 — see that
/// backend method's docs).
fn encrypt<B>(
    backend: &B,
    session: &ScpSession,
    dek: KeyHandle,
    new: KeyHandle,
) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    match session {
        ScpSession::Scp03(_) => Ok(backend.scp03_encrypt_put_key_payload(&dek, &new)?),
        ScpSession::Scp02(s) => {
            Ok(backend.scp02_encrypt_put_key_payload_for_session(&s.session(), &new)?)
        }
    }
}
