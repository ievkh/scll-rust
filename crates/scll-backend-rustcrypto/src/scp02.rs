//! `Scp02Backend` impl (PDD §3.3 / §4.2 / §5.9; GPCS v2.3.1 Appendix E, i=0x55).
//!
//! * Session keys (§E.4.1): `3DES-EDE2-CBC(constant(2) ‖ seq(2) ‖ 0x00…12,
//!   base_key, zero IV)` — full 16-byte output. Constants ENC=`0182`,
//!   MAC=`0101`, R-MAC=`0102`, DEK=`0181`; S-RMAC derives from the base MAC key.
//! * Card/host cryptograms (§E.4.4): full 3DES-CBC MAC under S-ENC over
//!   `host ‖ card8` / `card8 ‖ host` (last block), zero IV, where
//!   `card8 = sequence_counter(2) ‖ card_challenge(6)`.
//! * C-MAC (§E.4.4): ISO/IEC 9797-1:2011 Algorithm 3 "Retail MAC" under S-MAC
//!   over the modified header (`CLA|0x04`, `Lc' = Lc+8`) and the **plaintext**
//!   data. The per-command ICV is zero for EXTERNAL AUTHENTICATE and the
//!   single-DES-ECB encryption of the previous C-MAC thereafter (i=0x55 ICV
//!   encryption).
//! * C-DECRYPTION (§E.4.3): `3DES-EDE2-CBC` under S-ENC, zero IV, over the
//!   `0x80`-padded data; the transmitted `Lc` becomes `padded + 8`.
//! * PUT KEY (§E.5.2): `3DES-EDE2-ECB` of the new key under the DEK.
//!
//! The security level is latched from the EXTERNAL AUTHENTICATE `P1` (Fork F1,
//! as SCP03); on R-MAC failure the slot is invalidated and zeroized (Fork F3
//! tear-down). The wire algorithm mirrors `GlobalPlatformPro` `SCP02Wrapper` /
//! `GPCrypto` (validated against real JCOP cards) and is cross-checked by the
//! independent `tests/vectors/scp02_ref.py`. The default level `0x03`
//! (C-MAC + C-DECRYPTION) carries no response protection, so `unwrap` is a
//! pass-through there; the R-MAC branch (level `0x13`) follows GPCS §E.4.4 — a
//! single ISO/IEC 7816-4 pad (note: gppro's `unwrap` pre-pads before
//! `mac_des_3des`, double-padding; we follow the spec).
//!
//! `no_std`: `wrap`/`unwrap`/`encrypt_put_key_payload` return bounded
//! `heapless::Vec` (`CAPDU_MAX` / `RAPDU_MAX` / `ENC_KEY_BLOCK_MAX`).

use heapless::Vec;
use rand_core::{CryptoRng, RngCore};

use scll_core::backend::{KeyHandle, KeyKind, Scp02Backend, Scp02Session};
use scll_core::error::BackendError;
use scll_core::limits::{CAPDU_MAX, ENC_KEY_BLOCK_MAX, RAPDU_MAX};

use crate::crypto::{
    crypto_err, des_ecb_block, pad80_8, retail_mac, tdes_cbc_encrypt, tdes_ecb_block, tdes_mac,
    DES_BLOCK,
};
use crate::{BackendState, RustCryptoBackend, Scp02SessionSlot, SCP02_RMAC_BUF_MAX};

// Security-level bits (GPCS Table 10-1, constrained by Appendix E; EXTERNAL
// AUTHENTICATE P1). SCP02 default 0x03 = C-MAC + C-DECRYPTION. C-MAC is
// unconditional once authenticated; SCP02 has no R-ENC.
const SL_CDEC: u8 = 0x02;
const SL_RMAC: u8 = 0x10;

// Session-key derivation constants (GPCS §E.4.1; PlaintextKeys SCP02_CONSTANTS).
const DC_S_ENC: [u8; 2] = [0x01, 0x82];
const DC_S_MAC: [u8; 2] = [0x01, 0x01];
const DC_S_RMAC: [u8; 2] = [0x01, 0x02];
const DC_S_DEK: [u8; 2] = [0x01, 0x81];

const EXTERNAL_AUTHENTICATE: u8 = 0x82;
/// SCP02 session keys are always two-key 3DES (16 bytes).
const SCP02_KEY_LEN: usize = 16;

/// Constant-time equality, local to this module (the public `ct_eq` lives on
/// `KeyBackend`; calling it here would re-enter the state lock).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

fn push<const N: usize>(v: &mut Vec<u8, N>, src: &[u8]) -> Result<(), BackendError> {
    v.extend_from_slice(src)
        .map_err(|()| crypto_err("buffer overflow"))
}

fn zeroizing16(bytes: [u8; SCP02_KEY_LEN]) -> zeroize::Zeroizing<[u8; SCP02_KEY_LEN]> {
    zeroize::Zeroizing::new(bytes)
}

/// `Lc' = body + 8` (room for the trailing C-MAC), bounded to a short APDU.
fn lc_plus_mac(body_len: usize) -> Result<u8, BackendError> {
    let n = body_len
        .checked_add(8)
        .filter(|n| *n <= 255)
        .ok_or_else(|| crypto_err("wrapped Lc exceeds short APDU"))?;
    #[allow(clippy::cast_possible_truncation)] // bounded ≤255 just above
    Ok(n as u8)
}

/// Owned snapshot of one SCP02 session slot's fields, copied out so the crypto
/// helpers borrow nothing of `BackendState` while running.
struct Snap {
    s_enc: [u8; SCP02_KEY_LEN],
    s_mac: [u8; SCP02_KEY_LEN],
    s_rmac: [u8; SCP02_KEY_LEN],
    icv: [u8; 8],
    icv_valid: bool,
    ricv: [u8; 8],
    level: u8,
    authed: bool,
}

impl<R: RngCore + CryptoRng + Send + 'static> RustCryptoBackend<R> {
    /// Read the SCP02 session slot into an owned snapshot (without the R-MAC
    /// accumulation buffer, which is read separately only on the R-MAC path).
    fn scp02_snapshot(st: &BackendState<R>, s: Scp02Session) -> Result<Snap, BackendError> {
        let slot = st
            .scp02_sessions
            .get(usize::from(s.index()))
            .and_then(Option::as_ref)
            .ok_or_else(|| crypto_err("session handle invalid"))?;
        Ok(Snap {
            s_enc: *slot.s_enc,
            s_mac: *slot.s_mac,
            s_rmac: *slot.s_rmac,
            icv: slot.icv,
            icv_valid: slot.icv_valid,
            ricv: slot.ricv,
            level: slot.level,
            authed: slot.authed,
        })
    }

    /// Full 3DES-CBC MAC under S-ENC over `head ‖ tail` (zero IV) — the
    /// card/host cryptogram primitive shared by both directions.
    fn scp02_cryptogram(
        &self,
        s: Scp02Session,
        head: &[u8],
        tail: &[u8],
    ) -> Result<[u8; 8], BackendError> {
        self.with_state(|st| {
            let snap = Self::scp02_snapshot(st, s)?;
            let n = head.len() + tail.len();
            let mut input = [0u8; 16];
            if n > input.len() {
                return Err(crypto_err("cryptogram input too large"));
            }
            input[..head.len()].copy_from_slice(head);
            input[head.len()..n].copy_from_slice(tail);
            let mut scratch = [0u8; 24];
            tdes_mac(&snap.s_enc, [0u8; DES_BLOCK], &input[..n], &mut scratch)
        })
    }
}

impl<R: RngCore + CryptoRng + Send + 'static> Scp02Backend for RustCryptoBackend<R> {
    #[allow(clippy::similar_names)] // s_enc / s_mac / s_rmac / s_dek are the GP key names
    fn scp02_derive_session(
        &self,
        base_enc: &KeyHandle,
        base_mac: &KeyHandle,
        base_dek: &KeyHandle,
        seq_counter: [u8; 2],
    ) -> Result<Scp02Session, BackendError> {
        self.with_state(|st| {
            let enc = read_tdes_key(st, *base_enc)?;
            let mac = read_tdes_key(st, *base_mac)?;
            let dek = read_tdes_key(st, *base_dek)?;

            let s_enc = derive_one(&enc, DC_S_ENC, seq_counter)?;
            let s_mac = derive_one(&mac, DC_S_MAC, seq_counter)?;
            let s_rmac = derive_one(&mac, DC_S_RMAC, seq_counter)?; // from base MAC key
            let s_dek = derive_one(&dek, DC_S_DEK, seq_counter)?;

            let idx = st
                .scp02_sessions
                .iter()
                .position(Option::is_none)
                .ok_or_else(|| BackendError::KeyGen(short("session table full")))?;
            st.scp02_sessions[idx] = Some(Scp02SessionSlot {
                s_enc: zeroizing16(s_enc),
                s_mac: zeroizing16(s_mac),
                s_rmac: zeroizing16(s_rmac),
                s_dek: zeroizing16(s_dek),
                icv: [0u8; 8],
                icv_valid: false,
                ricv: [0u8; 8],
                rmac_buf: Vec::new(),
                level: 0,
                authed: false,
            });
            #[allow(clippy::cast_possible_truncation)] // idx < MAX_SESSION_SLOTS
            Ok(Scp02Session::new(idx as u16))
        })
    }

    fn scp02_card_cryptogram(
        &self,
        s: &Scp02Session,
        host_ch: &[u8; 8],
        card_ch: &[u8; 8],
    ) -> Result<[u8; 8], BackendError> {
        // card cryptogram: MAC over host(8) ‖ card8(8), where card8 =
        // sequence_counter ‖ card_challenge (GPCS v2.3.1 §E.4.4). 16-byte input.
        self.scp02_cryptogram(*s, host_ch, card_ch)
    }

    fn scp02_host_cryptogram(
        &self,
        s: &Scp02Session,
        host_ch: &[u8; 8],
        card_ch: &[u8; 8],
    ) -> Result<[u8; 8], BackendError> {
        // host cryptogram: MAC over card8(8) ‖ host(8), where card8 =
        // sequence_counter ‖ card_challenge (GPCS v2.3.1 §E.4.4). 16-byte input.
        self.scp02_cryptogram(*s, card_ch, host_ch)
    }

    fn scp02_wrap_command(
        &self,
        s: &mut Scp02Session,
        capdu: &[u8],
    ) -> Result<Vec<u8, CAPDU_MAX>, BackendError> {
        if capdu.len() < 4 {
            return Err(crypto_err("C-APDU shorter than header"));
        }
        let idx = usize::from(s.index());
        self.with_state(|st| {
            let snap = Self::scp02_snapshot(st, *s)?;
            let (cla, ins, p1, p2) = (capdu[0], capdu[1], capdu[2], capdu[3]);
            let has_lc = capdu.len() > 4;
            let data: &[u8] = if has_lc {
                let lc = usize::from(capdu[4]);
                capdu
                    .get(5..5 + lc)
                    .ok_or_else(|| crypto_err("C-APDU Lc exceeds buffer"))?
            } else {
                &[]
            };

            if !snap.authed && ins != EXTERNAL_AUTHENTICATE {
                return Err(crypto_err("first wrap must be EXTERNAL AUTHENTICATE"));
            }

            // 1. ICV for this command: zero on the first (EA) wrap; the
            //    single-DES-ECB (K1) encryption of the previous C-MAC after.
            let mut icv = [0u8; DES_BLOCK];
            if snap.icv_valid {
                des_ecb_block(&snap.s_mac[..DES_BLOCK], snap.icv, &mut icv)?;
            }

            // 2. C-MAC (Retail MAC) over the modified header + plaintext data,
            //    Lc' = Lc + 8.
            let new_cla = cla | 0x04;
            let mac_lc = lc_plus_mac(data.len())?;
            let mut mac_in = [0u8; 5 + 255];
            mac_in[..5].copy_from_slice(&[new_cla, ins, p1, p2, mac_lc]);
            mac_in
                .get_mut(5..5 + data.len())
                .ok_or_else(|| crypto_err("command data too large"))?
                .copy_from_slice(data);
            let mut mac_scratch = [0u8; 5 + 255 + DES_BLOCK];
            let cmac = retail_mac(
                &snap.s_mac,
                icv,
                &mac_in[..5 + data.len()],
                &mut mac_scratch,
            )?;

            // 3. Body: C-DECRYPTION (3DES-CBC under S-ENC, zero IV) when the
            //    latched level sets it and this is a post-auth command with data.
            let mut enc_scratch = [0u8; CAPDU_MAX];
            let body: &[u8] = if snap.authed && snap.level & SL_CDEC != 0 && !data.is_empty() {
                enc_scratch
                    .get_mut(..data.len())
                    .ok_or_else(|| crypto_err("command data too large"))?
                    .copy_from_slice(data);
                let padded = pad80_8(&mut enc_scratch, data.len())?;
                let n = tdes_cbc_encrypt(&snap.s_enc, [0u8; DES_BLOCK], &mut enc_scratch, padded)?;
                &enc_scratch[..n]
            } else {
                data
            };

            // 4. Assemble: newCLA INS P1 P2 (body+8) ‖ body ‖ C-MAC.
            let out_lc = lc_plus_mac(body.len())?;
            let mut out: Vec<u8, CAPDU_MAX> = Vec::new();
            push(&mut out, &[new_cla, ins, p1, p2, out_lc])?;
            push(&mut out, body)?;
            push(&mut out, &cmac)?;

            // 5. Commit. Latch the level from EA P1 on the first wrap (Fork F1).
            let latched = if snap.authed { snap.level } else { p1 };
            if let Some(slot) = st.scp02_sessions.get_mut(idx).and_then(Option::as_mut) {
                slot.icv = cmac;
                slot.icv_valid = true;
                slot.level = latched;
                // GPCS v2.3.1 §E.3.2 ("Message Integrity ICV using Explicit Secure
                // Channel Initiation"): after a successful EXTERNAL AUTHENTICATE, its
                // own C-MAC becomes the ICV for subsequent C-MAC verification *and/or
                // R-MAC generation*. The C-MAC chaining above already does this
                // (`slot.icv = cmac`); `ricv` — the R-MAC chaining value — must be
                // seeded the same way on this first wrap. Previously left at zero,
                // which only self-consistently matched the local KAT oracle (also
                // zero-seeded) rather than a spec-conformant card's first R-MAC
                // (flagged, not yet fixed, in CHANGELOG patch #10 / PDD §4.2).
                if !snap.authed {
                    slot.ricv = cmac;
                }
                // Accumulate post-auth commands for the R-MAC data block
                // (GPCS v2.3.1 §E.4.5): the *stripped* command — C-MAC removed and
                // the modified header undone, logical channel assumed zero
                // (`CLA & ~0x07`) — then `Lc ‖ data`. Per §E.4.5 the Lc byte is
                // ALWAYS present, set to zero for a case-1/2 (no-data) command, so
                // it is emitted unconditionally (a bare 4-byte header would
                // otherwise omit it). The EA pair is excluded (§E.4.5; snap.authed
                // is false there).
                if snap.authed && latched & SL_RMAC != 0 {
                    slot.rmac_buf.clear();
                    let _ = slot.rmac_buf.extend_from_slice(&[cla & !0x07, ins, p1, p2]);
                    #[allow(clippy::cast_possible_truncation)] // data.len() ≤ 255
                    let lc = data.len() as u8;
                    let _ = slot.rmac_buf.push(lc);
                    let _ = slot.rmac_buf.extend_from_slice(data);
                }
                slot.authed = true;
            }
            Ok(out)
        })
    }

    fn scp02_unwrap_response(
        &self,
        s: &mut Scp02Session,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
        let idx = usize::from(s.index());
        self.with_state(|st| {
            let snap = Self::scp02_snapshot(st, *s)?;

            // Fail-closed (Fork F3): any response-processing failure tears the
            // session down. SCP02 responses are unprotected at levels without
            // R-MAC, so those unwrap to `data ‖ SW` unchanged.
            let result: Result<(Vec<u8, RAPDU_MAX>, [u8; 8]), BackendError> = if !snap.authed {
                Err(crypto_err("unwrap before authentication"))
            } else if rapdu.len() < 2 {
                Err(crypto_err("R-APDU shorter than SW"))
            } else if snap.level & SL_RMAC != 0 {
                let rmac_cmd = st
                    .scp02_sessions
                    .get(idx)
                    .and_then(Option::as_ref)
                    .map(|slot| slot.rmac_buf.clone())
                    .ok_or_else(|| crypto_err("session handle invalid"))?;
                unwrap_rmac(&snap, &rmac_cmd, rapdu)
            } else {
                let mut out: Vec<u8, RAPDU_MAX> = Vec::new();
                push(&mut out, rapdu)?;
                Ok((out, snap.ricv))
            };

            match result {
                Ok((out, new_ricv)) => {
                    if let Some(slot) = st.scp02_sessions.get_mut(idx).and_then(Option::as_mut) {
                        slot.ricv = new_ricv;
                        slot.rmac_buf.clear();
                    }
                    Ok(out)
                }
                Err(e) => {
                    st.scp02_sessions[idx] = None;
                    Err(e)
                }
            }
        })
    }

    fn scp02_encrypt_put_key_payload_for_session(
        &self,
        s: &Scp02Session,
        new_key: &KeyHandle,
    ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError> {
        self.with_state(|st| {
            // Copy the session's derived DEK out first (short-lived borrow of
            // `st.scp02_sessions`), then read the new-key handle (a separate
            // borrow of `st.keys`).
            let dek_bytes: [u8; SCP02_KEY_LEN] = {
                let slot = st
                    .scp02_sessions
                    .get(usize::from(s.index()))
                    .and_then(Option::as_ref)
                    .ok_or_else(|| crypto_err("session handle invalid"))?;
                *slot.s_dek
            };
            let nk = read_tdes_key(st, *new_key)?;
            ecb_encrypt_put_key(&dek_bytes, &nk)
        })
    }

    fn scp02_close_session(&self, s: Scp02Session) {
        // Drop the slot; its `Scp02SessionSlot` keys/DEK/ICV are `Zeroizing`, so
        // assigning `None` wipes them. Out-of-range / already-free is a no-op.
        self.with_state(|st| {
            if let Some(slot) = st.scp02_sessions.get_mut(usize::from(s.index())) {
                *slot = None;
            }
        });
    }
}

/// One SCP02 session key: `3DES-CBC(constant ‖ seq ‖ 0x00…, base, zero IV)`,
/// the full 16-byte output (GPCS §E.4.1).
fn derive_one(
    base16: &[u8; SCP02_KEY_LEN],
    constant: [u8; 2],
    seq: [u8; 2],
) -> Result<[u8; SCP02_KEY_LEN], BackendError> {
    let mut buf = [0u8; SCP02_KEY_LEN];
    buf[0] = constant[0];
    buf[1] = constant[1];
    buf[2] = seq[0];
    buf[3] = seq[1];
    // bytes 4..16 already zero
    let n = tdes_cbc_encrypt(base16, [0u8; DES_BLOCK], &mut buf, SCP02_KEY_LEN)?;
    debug_assert_eq!(n, SCP02_KEY_LEN);
    Ok(buf)
}

/// R-MAC verify + strip (GPCS §E.4.4). On the wire the response data field is
/// `app_data ‖ R-MAC(8)`, followed by `SW(2)`. The MAC covers the accumulated
/// command ‖ `len(app_data) ‖ app_data ‖ SW`, chained from the previous R-MAC,
/// under S-RMAC (Retail MAC). Returns the stripped `app_data ‖ SW` and the new
/// R-MAC chaining value.
fn unwrap_rmac(
    snap: &Snap,
    rmac_cmd: &[u8],
    rapdu: &[u8],
) -> Result<(Vec<u8, RAPDU_MAX>, [u8; 8]), BackendError> {
    let split = rapdu.len() - 2;
    let sw = &rapdu[split..];
    let body = &rapdu[..split];
    if body.len() < 8 {
        return Err(crypto_err("R-APDU too short for R-MAC"));
    }
    let resp_len = body.len() - 8;
    let app_data = &body[..resp_len];
    let rmac_recv = &body[resp_len..];

    let mut input: Vec<u8, { SCP02_RMAC_BUF_MAX + 3 }> = Vec::new();
    push(&mut input, rmac_cmd)?;
    #[allow(clippy::cast_possible_truncation)] // resp_len ≤ RAPDU_MAX-2 ≤ 255
    let resp_len_byte = resp_len as u8;
    push(&mut input, &[resp_len_byte])?;
    push(&mut input, app_data)?;
    push(&mut input, sw)?;

    let mut scratch = [0u8; SCP02_RMAC_BUF_MAX + 3 + DES_BLOCK];
    let mac = retail_mac(&snap.s_rmac, snap.ricv, &input, &mut scratch)?;
    if !ct_eq(&mac, rmac_recv) {
        return Err(crypto_err("R-MAC verification failed"));
    }

    let mut out: Vec<u8, RAPDU_MAX> = Vec::new();
    push(&mut out, app_data)?;
    push(&mut out, sw)?;
    Ok((out, mac))
}

/// 3DES-EDE2-ECB-encrypt a 16-byte key under `dek_bytes` for a PUT KEY
/// payload (GPCS v2.3.1 §E.5.2). ECB ⇒ independent per-block encryption (no
/// chaining). Used by `scp02_encrypt_put_key_payload_for_session` (the
/// session's own derived DEK).
fn ecb_encrypt_put_key(
    dek_bytes: &[u8; SCP02_KEY_LEN],
    new_key_bytes: &[u8],
) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError> {
    let mut out: Vec<u8, ENC_KEY_BLOCK_MAX> = Vec::new();
    let mut block = [0u8; DES_BLOCK];
    let mut enc = [0u8; DES_BLOCK];
    for chunk in new_key_bytes.chunks(DES_BLOCK) {
        block.copy_from_slice(chunk);
        tdes_ecb_block(dek_bytes, block, &mut enc)?;
        push(&mut out, &enc)?;
    }
    Ok(out)
}

/// Read a two-key 3DES key by handle into an owned 16-byte buffer. Errors if the
/// handle is dangling or the slot is not a `TripleDesDouble` key.
fn read_tdes_key<R>(
    st: &BackendState<R>,
    h: KeyHandle,
) -> Result<[u8; SCP02_KEY_LEN], BackendError> {
    let slot = st
        .keys
        .get(usize::from(h.index()))
        .and_then(Option::as_ref)
        .ok_or_else(|| crypto_err("key handle invalid"))?;
    if slot.kind != KeyKind::TripleDesDouble {
        return Err(crypto_err("SCP02 needs a 3DES double-length key"));
    }
    let key = slot.key();
    if key.len() != SCP02_KEY_LEN {
        return Err(crypto_err("3DES key not 16 bytes"));
    }
    let mut buf = [0u8; SCP02_KEY_LEN];
    buf.copy_from_slice(key);
    Ok(buf)
}

fn short(msg: &str) -> heapless::String<{ scll_core::limits::OTHER_DETAIL_MAX }> {
    let mut s = heapless::String::new();
    let _ = s.push_str(msg);
    s
}
