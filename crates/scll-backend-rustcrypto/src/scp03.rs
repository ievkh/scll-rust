//! `Scp03Backend` impl (PDD §3.3 / §4.1 / §5.9; Amendment D v1.1.2).
//!
//! Session keys via the SP 800-108r1 CMAC counter-mode KDF (§4.1.5,
//! [`crate::crypto::kdf`]); card/host cryptograms keyed by S-MAC (§6.2.2.2/3);
//! C-MAC chaining persists across C-MAC and R-MAC (§6.2.3); command/response
//! encryption is AES-CBC under S-ENC with an ECB-derived ICV (§6.2.6/§6.2.7);
//! PUT KEY uses the static DEK (§6.2.6). Security level is latched from the
//! EXTERNAL AUTHENTICATE `P1` (Fork F1); on R-MAC/decrypt failure the session
//! slot is invalidated and zeroized (Fork F3, §4.1 tear-down).
//!
//! `no_std`: `wrap`/`unwrap`/`encrypt_put_key_payload` return bounded
//! `heapless::Vec` (`CAPDU_MAX` / `RAPDU_MAX` / `ENC_KEY_BLOCK_MAX`).

use heapless::Vec;
use rand_core::{CryptoRng, RngCore};

use scll_core::backend::{KeyHandle, Scp03Backend, Scp03Session, ScpMode};
use scll_core::error::BackendError;
use scll_core::limits::{
    CAPDU_MAX, ENC_KEY_BLOCK_MAX, KEY_BYTES_MAX, MAC_CHAIN_LEN, RAPDU_MAX, SCP03_S16_MAX,
};

use crate::crypto::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_cmac, aes_ecb_block, crypto_err, kdf, pad80, unpad80,
    BLOCK,
};
use crate::{BackendState, RustCryptoBackend, Scp03SessionSlot};

// Security-level bits (GPCS Table 10-1 / Amendment D §6.2; EXTERNAL
// AUTHENTICATE P1). Default 0x33 = C-MAC + C-DEC + R-MAC + R-ENC (§4.1). C-MAC
// is unconditional once authenticated (all capped levels set it), so only the
// optional bits are tested below.
const SL_CENC: u8 = 0x02;
const SL_RMAC: u8 = 0x10;
const SL_RENC: u8 = 0x20;

// KDF derivation constants (Amendment D Table 4-1).
const DC_S_ENC: u8 = 0x04;
const DC_S_MAC: u8 = 0x06;
const DC_S_RMAC: u8 = 0x07;
const DC_CARD_CRYPTO: u8 = 0x00;
const DC_HOST_CRYPTO: u8 = 0x01;
/// Card-challenge derivation constant for pseudo-random challenges
/// (Amendment D Table 4-1 / §6.2.2.1).
const DC_CARD_CHALLENGE: u8 = 0x02;

const EXTERNAL_AUTHENTICATE: u8 = 0x82;

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

/// `host_challenge ‖ card_challenge` — the KDF context for all SCP03
/// derivations (Amendment D §4.1.5). 16 bytes in S8, 32 bytes in S16.
fn context(host: &[u8], card: &[u8]) -> Result<Vec<u8, 32>, BackendError> {
    let mut ctx: Vec<u8, 32> = Vec::new();
    ctx.extend_from_slice(host)
        .map_err(|()| crypto_err("context overflow"))?;
    ctx.extend_from_slice(card)
        .map_err(|()| crypto_err("context overflow"))?;
    Ok(ctx)
}

/// The 16-byte block fed to AES-ECB to derive the CBC ICV: the command counter
/// as a big-endian integer, with byte 0 forced to `0x80` for responses
/// (Amendment D §6.2.6 command / §6.2.7 response).
fn counter_block(counter: u32, response: bool) -> [u8; BLOCK] {
    let mut blk = [0u8; BLOCK];
    blk[BLOCK - 4..].copy_from_slice(&counter.to_be_bytes());
    if response {
        blk[0] = 0x80;
    }
    blk
}

/// `(session keys, mode, MAC chaining value, command counter, security level,
/// authenticated)` — the per-call snapshot returned by `session_snapshot`.
type SessionSnapshot = (SessionKeys, ScpMode, [u8; MAC_CHAIN_LEN], u32, u8, bool);

/// Snapshot of the immutable-for-this-call session key material, copied out of
/// the locked slot so the crypto helpers can borrow it without holding the
/// `BackendState` borrow.
struct SessionKeys {
    s_enc: [u8; KEY_BYTES_MAX],
    s_mac: [u8; KEY_BYTES_MAX],
    s_rmac: [u8; KEY_BYTES_MAX],
    key_len: usize,
}

impl SessionKeys {
    fn enc(&self) -> &[u8] {
        &self.s_enc[..self.key_len]
    }
    fn mac(&self) -> &[u8] {
        &self.s_mac[..self.key_len]
    }
    fn rmac(&self) -> &[u8] {
        &self.s_rmac[..self.key_len]
    }
}

impl<R: RngCore + CryptoRng + Send + 'static> RustCryptoBackend<R> {
    /// Read the session slot keys into an owned snapshot, returning the slot's
    /// `(mode, chain, counter, level, authed)` alongside.
    fn session_snapshot(
        st: &BackendState<R>,
        s: Scp03Session,
    ) -> Result<SessionSnapshot, BackendError> {
        let slot = st
            .sessions
            .get(usize::from(s.index()))
            .and_then(Option::as_ref)
            .ok_or_else(|| crypto_err("session handle invalid"))?;
        let mut keys = SessionKeys {
            s_enc: [0u8; KEY_BYTES_MAX],
            s_mac: [0u8; KEY_BYTES_MAX],
            s_rmac: [0u8; KEY_BYTES_MAX],
            key_len: usize::from(slot.key_len),
        };
        keys.s_enc[..keys.key_len].copy_from_slice(slot.s_enc());
        keys.s_mac[..keys.key_len].copy_from_slice(slot.s_mac());
        keys.s_rmac[..keys.key_len].copy_from_slice(slot.s_rmac());
        Ok((
            keys,
            slot.mode,
            slot.chain,
            slot.counter,
            slot.level,
            slot.authed,
        ))
    }
}

impl<R: RngCore + CryptoRng + Send + 'static> Scp03Backend for RustCryptoBackend<R> {
    #[allow(clippy::similar_names)] // s_enc / s_mac / s_rmac are the GP key names
    fn scp03_derive_session(
        &self,
        static_enc: &KeyHandle,
        static_mac: &KeyHandle,
        mode: ScpMode,
        host_challenge: &[u8],
        card_challenge: &[u8],
    ) -> Result<Scp03Session, BackendError> {
        // Reject challenge lengths that disagree with the mode (8 / 16 bytes).
        if host_challenge.len() != mode.field_len() || card_challenge.len() != mode.field_len() {
            return Err(crypto_err("challenge length does not match mode"));
        }
        let ctx = context(host_challenge, card_challenge)?;
        self.with_state(|st| {
            // Copy the two static keys out first so the session write below does
            // not collide with the key-table read borrow.
            let (enc, enc_len) = read_aes_key(st, *static_enc)?;
            let (mac, mac_len) = read_aes_key(st, *static_mac)?;
            if enc_len != mac_len {
                return Err(crypto_err("ENC/MAC key lengths differ"));
            }
            let key_len = enc_len;
            #[allow(clippy::cast_possible_truncation)] // key_len ∈ {16,24,32}
            let l_bits = (key_len as u16) * 8;

            let mut s_enc = [0u8; KEY_BYTES_MAX];
            let mut s_mac = [0u8; KEY_BYTES_MAX];
            let mut s_rmac = [0u8; KEY_BYTES_MAX];
            kdf(
                &enc[..key_len],
                DC_S_ENC,
                l_bits,
                &ctx,
                &mut s_enc[..key_len],
            )?;
            kdf(
                &mac[..key_len],
                DC_S_MAC,
                l_bits,
                &ctx,
                &mut s_mac[..key_len],
            )?;
            kdf(
                &mac[..key_len],
                DC_S_RMAC,
                l_bits,
                &ctx,
                &mut s_rmac[..key_len],
            )?;

            let idx = st
                .sessions
                .iter()
                .position(Option::is_none)
                .ok_or_else(|| BackendError::KeyGen(crate_short("session table full")))?;
            #[allow(clippy::cast_possible_truncation)] // key_len ∈ {16,24,32}
            let key_len_u8 = key_len as u8;
            st.sessions[idx] = Some(Scp03SessionSlot {
                s_enc: zeroizing(s_enc),
                s_mac: zeroizing(s_mac),
                s_rmac: zeroizing(s_rmac),
                key_len: key_len_u8,
                mode,
                chain: [0u8; MAC_CHAIN_LEN],
                counter: 0,
                level: 0,
                authed: false,
            });
            #[allow(clippy::cast_possible_truncation)] // idx < MAX_SESSION_SLOTS
            Ok(Scp03Session::new(idx as u16))
        })
    }

    fn scp03_card_cryptogram(
        &self,
        s: &Scp03Session,
        host_ch: &[u8],
        card_ch: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
        self.cryptogram(*s, host_ch, card_ch, DC_CARD_CRYPTO)
    }

    fn scp03_host_cryptogram(
        &self,
        s: &Scp03Session,
        host_ch: &[u8],
        card_ch: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
        self.cryptogram(*s, host_ch, card_ch, DC_HOST_CRYPTO)
    }

    fn scp03_pseudo_card_challenge(
        &self,
        static_enc: &KeyHandle,
        mode: ScpMode,
        seq_counter: &[u8; 3],
        invoker_aid: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
        // Context = sequence_counter(3) ‖ invoker_AID(5..16) (Amendment D
        // §6.2.2.1); keyed by the static Key-ENC, derivation constant 0x02.
        let mut ctx: Vec<u8, 19> = Vec::new();
        ctx.extend_from_slice(seq_counter)
            .map_err(|()| crypto_err("challenge context overflow"))?;
        ctx.extend_from_slice(invoker_aid)
            .map_err(|()| crypto_err("challenge context overflow"))?;
        let len = mode.field_len();
        self.with_state(|st| {
            let (enc, enc_len) = read_aes_key(st, *static_enc)?;
            let mut buf = [0u8; SCP03_S16_MAX];
            kdf(
                &enc[..enc_len],
                DC_CARD_CHALLENGE,
                mode.l_bits(),
                &ctx,
                &mut buf[..len],
            )?;
            let mut out: Vec<u8, SCP03_S16_MAX> = Vec::new();
            out.extend_from_slice(&buf[..len])
                .map_err(|()| crypto_err("challenge overflow"))?;
            Ok(out)
        })
    }

    fn scp03_wrap_command(
        &self,
        s: &mut Scp03Session,
        capdu: &[u8],
    ) -> Result<Vec<u8, CAPDU_MAX>, BackendError> {
        if capdu.len() < 4 {
            return Err(crypto_err("C-APDU shorter than header"));
        }
        let idx = usize::from(s.index());
        self.with_state(|st| {
            let (keys, mode, mut chain, mut counter, mut level, authed) =
                Self::session_snapshot(st, *s)?;
            let mac_len = mode.mac_len();

            let (cla, ins, p1, p2) = (capdu[0], capdu[1], capdu[2], capdu[3]);
            // GlobalPlatform secure-messaging bit (b3): the C-MAC is computed
            // over, and the command is transmitted with, `CLA | 0x04`
            // (0x80 -> 0x84). Amendment D §6.2.4 (the MAC input header begins
            // with '84'); a card rejects a MAC'd command sent with CLA 0x80.
            let new_cla = cla | 0x04;
            let lc = if capdu.len() > 4 {
                usize::from(capdu[4])
            } else {
                0
            };
            let data: &[u8] = if capdu.len() > 4 {
                capdu
                    .get(5..5 + lc)
                    .ok_or_else(|| crypto_err("C-APDU Lc exceeds buffer"))?
            } else {
                &[]
            };
            // Trailing Le (Case 4 commands such as GET STATUS) is preserved
            // verbatim after the C-MAC. Le is NOT part of the MAC input.
            let le: &[u8] = capdu.get(5 + lc..).unwrap_or(&[]);

            // Body = data, encrypted under S-ENC when C-DECRYPTION is active and
            // this is not the (never-encrypted) EXTERNAL AUTHENTICATE.
            let mut scratch = [0u8; CAPDU_MAX];
            let body: &[u8];
            if authed {
                counter = counter
                    .checked_add(1)
                    .ok_or_else(|| crypto_err("command counter overflow"))?;
                if level & SL_CENC != 0 && !data.is_empty() {
                    scratch
                        .get_mut(..data.len())
                        .ok_or_else(|| crypto_err("command data too large"))?
                        .copy_from_slice(data);
                    let padded = pad80(&mut scratch, data.len())?;
                    let icv = ecb_icv(keys.enc(), counter, false)?;
                    let n = aes_cbc_encrypt(keys.enc(), &icv, &mut scratch, padded)?;
                    body = &scratch[..n];
                } else {
                    body = data;
                }
            } else {
                // EXTERNAL AUTHENTICATE: latch the fixed level from P1 (Fork F1);
                // never encrypted, only C-MAC. The first wrap on a fresh session
                // must be EA.
                if ins != EXTERNAL_AUTHENTICATE {
                    return Err(crypto_err("first wrap must be EXTERNAL AUTHENTICATE"));
                }
                level = p1;
                body = data;
            }

            // C-MAC over: chaining value ‖ {CLA INS P1 P2 Lc'} ‖ body, where Lc'
            // already includes the appended MAC (8 in S8, 16 in S16; §6.2.3/§6.2.4).
            let lc_prime = body
                .len()
                .checked_add(mac_len)
                .filter(|n| *n <= 255)
                .ok_or_else(|| crypto_err("wrapped Lc exceeds short APDU"))?;
            #[allow(clippy::cast_possible_truncation)] // bounded ≤255 just above
            let lc_byte = lc_prime as u8;

            let mut mac_in: Vec<u8, 320> = Vec::new();
            push(&mut mac_in, &chain)?;
            push(&mut mac_in, &[new_cla, ins, p1, p2, lc_byte])?;
            push(&mut mac_in, body)?;
            let mut full = [0u8; BLOCK];
            aes_cmac(keys.mac(), &mac_in, &mut full)?;
            chain = full; // full 16-byte C-MAC becomes the new chaining value

            let mut out: Vec<u8, CAPDU_MAX> = Vec::new();
            push(&mut out, &[new_cla, ins, p1, p2, lc_byte])?;
            push(&mut out, body)?;
            push(&mut out, &full[..mac_len])?;
            push(&mut out, le)?; // re-append Le (Case 4); empty for Case 3

            // Commit the mutated session fields.
            if let Some(slot) = st.sessions.get_mut(idx).and_then(Option::as_mut) {
                slot.chain = chain;
                slot.counter = counter;
                slot.level = level;
                slot.authed = true;
            }
            Ok(out)
        })
    }

    fn scp03_unwrap_response(
        &self,
        s: &mut Scp03Session,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
        let idx = usize::from(s.index());
        self.with_state(|st| {
            // A live session is required; if the handle is already dead the
            // snapshot fails and there is nothing left to tear down.
            let (keys, mode, chain, counter, level, authed) = Self::session_snapshot(st, *s)?;
            let mac_len = mode.mac_len();

            // Fail-closed (Fork F3): ANY response-processing failure — framing
            // (too short for SW), pre-authentication use, R-MAC mismatch, or
            // decrypt/unpad — aborts the secure channel. The error is already a
            // `BackendError::Crypto`, so tearing down on all of them keeps the
            // contract consistent: a failed unwrap always invalidates + zeroizes
            // the session slot.
            let result = if !authed {
                Err(crypto_err("unwrap before authentication"))
            } else if rapdu.len() < 2 {
                Err(crypto_err("R-APDU shorter than SW"))
            } else {
                unwrap_inner(&keys, &chain, counter, level, mac_len, rapdu)
            };
            if result.is_err() {
                st.sessions[idx] = None;
            }
            result
        })
    }

    fn scp03_encrypt_put_key_payload(
        &self,
        dek: &KeyHandle,
        new_key: &KeyHandle,
    ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError> {
        self.with_state(|st| {
            let (dek_bytes, dek_len) = read_aes_key(st, *dek)?;
            let (nk_bytes, nk_len) = read_aes_key(st, *new_key)?;

            // Encrypt the new key under the static DEK, AES-CBC, zero ICV
            // (Amendment D §6.2.6). Block-aligned keys (16/32) carry no padding;
            // a 24-byte AES-192 key is 0x80-padded to the block boundary.
            let mut scratch = [0u8; ENC_KEY_BLOCK_MAX];
            scratch
                .get_mut(..nk_len)
                .ok_or_else(|| crypto_err("new key too large"))?
                .copy_from_slice(&nk_bytes[..nk_len]);
            let msg_len = if nk_len % BLOCK == 0 {
                nk_len
            } else {
                pad80(&mut scratch, nk_len)?
            };
            let iv = [0u8; BLOCK];
            let n = aes_cbc_encrypt(&dek_bytes[..dek_len], &iv, &mut scratch, msg_len)?;

            let mut out: Vec<u8, ENC_KEY_BLOCK_MAX> = Vec::new();
            out.extend_from_slice(&scratch[..n])
                .map_err(|()| crypto_err("enc key block overflow"))?;
            Ok(out)
        })
    }

    fn scp03_close_session(&self, s: Scp03Session) {
        // Drop the slot; its `Scp03SessionSlot` keys/chain are `Zeroizing`, so
        // assigning `None` wipes them. Out-of-range / already-free is a no-op.
        self.with_state(|st| {
            if let Some(slot) = st.sessions.get_mut(usize::from(s.index())) {
                *slot = None;
            }
        });
    }
}

impl<R: RngCore + CryptoRng + Send + 'static> RustCryptoBackend<R> {
    /// Shared card/host cryptogram: KDF keyed by S-MAC, `mode.field_len()`-byte
    /// output (`L = mode.l_bits()`), constant `0x00` (card) / `0x01` (host)
    /// (Amendment D §6.2.2). 8 bytes in S8, 16 bytes in S16.
    fn cryptogram(
        &self,
        s: Scp03Session,
        host_ch: &[u8],
        card_ch: &[u8],
        constant: u8,
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
        let ctx = context(host_ch, card_ch)?;
        self.with_state(|st| {
            let (keys, mode, ..) = Self::session_snapshot(st, s)?;
            let len = mode.field_len();
            let mut buf = [0u8; SCP03_S16_MAX];
            kdf(keys.mac(), constant, mode.l_bits(), &ctx, &mut buf[..len])?;
            let mut out: Vec<u8, SCP03_S16_MAX> = Vec::new();
            out.extend_from_slice(&buf[..len])
                .map_err(|()| crypto_err("cryptogram overflow"))?;
            Ok(out)
        })
    }
}

/// Read an AES key by handle into an owned buffer, returning `(bytes, len)`.
/// Errors if the handle is dangling or the slot is a non-AES (3DES) key.
fn read_aes_key<R>(
    st: &BackendState<R>,
    h: KeyHandle,
) -> Result<([u8; KEY_BYTES_MAX], usize), BackendError> {
    use scll_core::backend::KeyKind;
    let slot = st
        .keys
        .get(usize::from(h.index()))
        .and_then(Option::as_ref)
        .ok_or_else(|| crypto_err("key handle invalid"))?;
    match slot.kind {
        KeyKind::Aes128 | KeyKind::Aes192 | KeyKind::Aes256 => {}
        _ => return Err(crypto_err("SCP03 needs an AES key")),
    }
    let mut buf = [0u8; KEY_BYTES_MAX];
    let len = usize::from(slot.len);
    buf[..len].copy_from_slice(slot.key());
    Ok((buf, len))
}

/// AES-ECB-derived CBC ICV for command (`response = false`) or response data.
fn ecb_icv(key: &[u8], counter: u32, response: bool) -> Result<[u8; BLOCK], BackendError> {
    let block = counter_block(counter, response);
    let mut icv = [0u8; BLOCK];
    aes_ecb_block(key, &block, &mut icv)?;
    Ok(icv)
}

/// Response verify+strip (R-MAC) and decrypt (R-ENC), pure over a key snapshot.
/// On the wire a protected response is `data ‖ R-MAC(8) ‖ SW(2)`; the MAC covers
/// `chain ‖ data ‖ SW` (Amendment D §6.2.5). R-MAC does not advance the
/// chaining value.
///
/// Per Amendment D §6.2.5, R-MAC (and, §6.2.7, R-ENC) are applied **only** to a
/// success (`9000`) or warning (`62xx`/`63xx`) status word; every other (error)
/// status word is returned bare — status word only, no R-MAC, no R-ENC — so it
/// is passed through unverified rather than rejected for being "too short".
fn unwrap_inner(
    keys: &SessionKeys,
    chain: &[u8; MAC_CHAIN_LEN],
    counter: u32,
    level: u8,
    mac_len: usize,
    rapdu: &[u8],
) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
    let split = rapdu.len() - 2;
    let sw = &rapdu[split..];
    let body = &rapdu[..split];

    // Amendment D §6.2.5: protection is present only for '9000' and the warning
    // status words '62xx'/'63xx'. Any other SW is an error SW and is returned
    // bare (no R-MAC / no R-ENC).
    let protected = sw_is_protected(sw);

    let data: &[u8] = if level & SL_RMAC != 0 && protected {
        if body.len() < mac_len {
            return Err(crypto_err("R-APDU too short for R-MAC"));
        }
        let (data, rmac) = body.split_at(body.len() - mac_len);
        let mut mac_in: Vec<u8, { RAPDU_MAX + MAC_CHAIN_LEN }> = Vec::new();
        push(&mut mac_in, chain)?;
        push(&mut mac_in, data)?;
        push(&mut mac_in, sw)?;
        let mut full = [0u8; BLOCK];
        aes_cmac(keys.rmac(), &mac_in, &mut full)?;
        if !ct_eq(&full[..mac_len], rmac) {
            return Err(crypto_err("R-MAC verification failed"));
        }
        data
    } else {
        body
    };

    let mut out: Vec<u8, RAPDU_MAX> = Vec::new();
    if level & SL_RENC != 0 && protected && !data.is_empty() {
        if data.len() % BLOCK != 0 {
            return Err(crypto_err("R-ENC data not block-aligned"));
        }
        let icv = ecb_icv(keys.enc(), counter, true)?;
        let mut scratch = [0u8; RAPDU_MAX];
        scratch
            .get_mut(..data.len())
            .ok_or_else(|| crypto_err("response data too large"))?
            .copy_from_slice(data);
        aes_cbc_decrypt(keys.enc(), &icv, &mut scratch[..data.len()])?;
        let plain_len = unpad80(&scratch[..data.len()])?;
        push(&mut out, &scratch[..plain_len])?;
    } else {
        push(&mut out, data)?;
    }
    push(&mut out, sw)?;
    Ok(out)
}

/// Whether the response status word carries R-MAC/R-ENC protection.
/// Amendment D §6.2.5: only `9000` and the warning status words `62xx`/`63xx`
/// are protected; every other status word is an error SW returned bare.
fn sw_is_protected(sw: &[u8]) -> bool {
    matches!(sw, [0x90, 0x00] | [0x62 | 0x63, _])
}

fn push<const N: usize>(v: &mut Vec<u8, N>, src: &[u8]) -> Result<(), BackendError> {
    v.extend_from_slice(src)
        .map_err(|()| crypto_err("buffer overflow"))
}

fn zeroizing(bytes: [u8; KEY_BYTES_MAX]) -> zeroize::Zeroizing<[u8; KEY_BYTES_MAX]> {
    zeroize::Zeroizing::new(bytes)
}

fn crate_short(msg: &str) -> heapless::String<{ scll_core::limits::OTHER_DETAIL_MAX }> {
    let mut s = heapless::String::new();
    let _ = s.push_str(msg);
    s
}
