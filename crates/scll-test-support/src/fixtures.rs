//! Synthetic, spec-faithful APDU fixtures for replay tests (PDD §10.3).
//!
//! These build the `GlobalPlatform` response templates (FCI, Card Recognition
//! Data, INITIALIZE UPDATE responses, GET STATUS `'E3'`) that a card would
//! return, so replay tests can drive the real workflow code path without a
//! card or simulator. They are **synthetic** — constructed from the GPCS
//! v2.3.1 template layouts (§H.2/§11.3.3.1/§11.4) and the SCP02/SCP03 IU
//! response shapes (PDD §5.9) — and are explicitly marked for replacement by
//! live captures (jcsim / `gp -d`) before the S6 exit gate is claimed against
//! real silicon (PDD §10.3).

/// Append a status word to a data field, yielding a full R-APDU (`data ‖ SW`).
#[must_use]
pub fn rapdu(data: &[u8], sw: u16) -> std::vec::Vec<u8> {
    let mut v = data.to_vec();
    v.extend_from_slice(&sw.to_be_bytes());
    v
}

/// A status-word-only R-APDU (no data), e.g. an EXTERNAL AUTHENTICATE answer.
#[must_use]
pub fn sw(sw: u16) -> std::vec::Vec<u8> {
    sw.to_be_bytes().to_vec()
}

/// FCI carrying an ISD AID under tag `'84'`: `6F Lc 84 La <aid>` (ISO 7816-4 §7.4).
///
/// # Panics
/// Panics if `aid` is longer than 255 bytes (never true for a valid 5..=16-byte AID).
#[must_use]
pub fn fci_with_aid(aid: &[u8]) -> std::vec::Vec<u8> {
    let mut v = std::vec::Vec::new();
    let la = u8::try_from(aid.len()).expect("AID length fits in u8");
    v.extend_from_slice(&[0x6F, la + 2, 0x84, la]);
    v.extend_from_slice(aid);
    v
}

/// Card Recognition Data advertising one SCP03 variant with `i = i_param`
/// (`'66'→'73'→'64'→'06'` with OID tail `03 i`; GPCS v2.3.1 §H.2).
#[must_use]
pub fn crd_scp03(i_param: u8) -> std::vec::Vec<u8> {
    vec![
        0x66, 0x0E, 0x73, 0x0C, 0x64, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03,
        i_param,
    ]
}

/// Card Recognition Data advertising one SCP02 variant with `i = i_param`
/// (OID tail `02 i`; GPCS v2.3.1 §H.2).
#[must_use]
pub fn crd_scp02(i_param: u8) -> std::vec::Vec<u8> {
    vec![
        0x66, 0x0E, 0x73, 0x0C, 0x64, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02,
        i_param,
    ]
}

/// Key Information Template: one keyset (KVN 1, KIDs 1/2/3, AES, 16 B)
/// (`'E0'{ 'C0'{0k 01 88 10}×3 }` — KID first, then KVN; GPCS v2.3.1
/// §11.3.3.1, Table 11-70).
#[must_use]
pub fn kit_aes_kvn1() -> std::vec::Vec<u8> {
    vec![
        0xE0, 0x12, 0xC0, 0x04, 0x01, 0x01, 0x88, 0x10, 0xC0, 0x04, 0x02, 0x01, 0x88, 0x10, 0xC0,
        0x04, 0x03, 0x01, 0x88, 0x10,
    ]
}

/// Card Capability Information: 4 logical channels + ISD privilege byte
/// (`'67'{ 'A0'{04} 'A3'{80 00 00} }`; GPCS v2.3.1 §H.4).
#[must_use]
pub fn cci_basic() -> std::vec::Vec<u8> {
    vec![0x67, 0x08, 0xA0, 0x01, 0x04, 0xA3, 0x03, 0x80, 0x00, 0x00]
}

/// SCP03 INITIALIZE UPDATE response (SW stripped):
/// `KDD(10) KVN SCP=03 i card_challenge(8) card_cryptogram(8)`, plus a trailing
/// 3-byte sequence counter when `i` selects pseudo-random challenges
/// (`i & 0x10`; Amendment D §6.2.2.1 / §7.1.1.6). So a random-challenge `i`
/// yields 29 bytes and a pseudo-random `i` yields 32 bytes (PDD §5.9).
#[must_use]
pub fn iu_scp03(
    kvn: u8,
    i_param: u8,
    challenge: [u8; 8],
    cryptogram: [u8; 8],
) -> std::vec::Vec<u8> {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&[0u8; 10]); // key diversification data
    b.push(kvn);
    b.push(0x03);
    b.push(i_param);
    b.extend_from_slice(&challenge);
    b.extend_from_slice(&cryptogram);
    if i_param & 0x10 != 0 {
        // Pseudo-random challenge ⇒ 3-byte sequence counter follows.
        b.extend_from_slice(&[0x00, 0x00, 0x01]);
    }
    b
}

/// SCP02 INITIALIZE UPDATE response (SW stripped), 28 bytes:
/// `KDD(10) KVN SCP=02 seq(2) card_challenge(6) card_cryptogram(8)` (PDD §5.9).
#[must_use]
pub fn iu_scp02(
    kvn: u8,
    seq: [u8; 2],
    challenge: [u8; 6],
    cryptogram: [u8; 8],
) -> std::vec::Vec<u8> {
    let mut b = [0u8; 28];
    b[10] = kvn;
    b[11] = 0x02;
    b[12..14].copy_from_slice(&seq);
    b[14..20].copy_from_slice(&challenge);
    b[20..28].copy_from_slice(&cryptogram);
    b.to_vec()
}

/// GET STATUS `'E3'` registry entry carrying a life-cycle byte
/// (`E3{ 4F{A000000003 0000} 9F70{lc} }`; GPCS v2.3.1 Table 11-36 / Table 11-6).
#[must_use]
pub fn status_e3(life_cycle: u8) -> std::vec::Vec<u8> {
    vec![
        0xE3, 0x0D, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x9F, 0x70, 0x01,
        life_cycle,
    ]
}

/// PUT KEY KCV echo: `new_kvn ‖ KCV ‖ KCV ‖ KCV` (one KCV per key; GPCS §11.8.3.1).
#[must_use]
pub fn put_key_echo(new_kvn: u8, kcv: [u8; 3]) -> std::vec::Vec<u8> {
    let mut v = std::vec::Vec::new();
    v.push(new_kvn);
    for _ in 0..3 {
        v.extend_from_slice(&kcv);
    }
    v
}

/// A GET STATUS `'E3'` registry entry for an Application or Security Domain:
/// `E3{ 4F<aid> 9F70<lc> C5<privileges> }` (GPCS v2.3.1 Table 11-36). `privs` is
/// 1 or 3 bytes; the Security Domain bit is byte-1 / b8 (`0x80`), so a non-empty
/// `privs[0] & 0x80` marks an SD.
///
/// # Panics
/// Panics if `aid` or `privs` is longer than 255 bytes (never true for valid
/// GET STATUS data).
#[must_use]
pub fn status_e3_app(aid: &[u8], life_cycle: u8, privs: &[u8]) -> std::vec::Vec<u8> {
    let mut inner = std::vec::Vec::new();
    inner.push(0x4F);
    inner.push(u8::try_from(aid.len()).expect("AID fits u8"));
    inner.extend_from_slice(aid);
    inner.extend_from_slice(&[0x9F, 0x70, 0x01, life_cycle]);
    inner.push(0xC5);
    inner.push(u8::try_from(privs.len()).expect("privileges fit u8"));
    inner.extend_from_slice(privs);
    wrap_e3(&inner)
}

/// A GET STATUS `'E3'` registry entry for an Executable Load File and its
/// modules: `E3{ 4F<elf> 9F70<lc> CC<assoc_sd> 84<mod>… }` (GPCS v2.3.1
/// Table 11-36 / 11-37). Pass `&[]` for `assoc_sd` to omit the `'CC'` tag.
///
/// # Panics
/// Panics if any field is longer than 255 bytes.
#[must_use]
pub fn status_e3_elf(
    elf: &[u8],
    life_cycle: u8,
    assoc_sd: &[u8],
    modules: &[&[u8]],
) -> std::vec::Vec<u8> {
    let mut inner = std::vec::Vec::new();
    inner.push(0x4F);
    inner.push(u8::try_from(elf.len()).expect("AID fits u8"));
    inner.extend_from_slice(elf);
    inner.extend_from_slice(&[0x9F, 0x70, 0x01, life_cycle]);
    if !assoc_sd.is_empty() {
        inner.push(0xCC);
        inner.push(u8::try_from(assoc_sd.len()).expect("AID fits u8"));
        inner.extend_from_slice(assoc_sd);
    }
    for m in modules {
        inner.push(0x84);
        inner.push(u8::try_from(m.len()).expect("AID fits u8"));
        inner.extend_from_slice(m);
    }
    wrap_e3(&inner)
}

/// Wrap an `'E3'` body (the registry-entry sub-tags) in its tag + BER length
/// (short form `< 128`, else long form `81 LL`), so bodies longer than 127
/// bytes — an ELF with many modules — still parse.
fn wrap_e3(inner: &[u8]) -> std::vec::Vec<u8> {
    let mut v = std::vec::Vec::new();
    v.push(0xE3);
    push_ber_len(&mut v, inner.len());
    v.extend_from_slice(inner);
    v
}

/// Append a definite BER-TLV length: short form for `< 128`, else `81 LL`
/// (one length octet — fixtures never exceed 255 bytes).
///
/// # Panics
/// Panics if `len > 255` (no fixture body is that large).
fn push_ber_len(v: &mut std::vec::Vec<u8>, len: usize) {
    if len < 0x80 {
        v.push(u8::try_from(len).expect("short BER length fits u8"));
    } else {
        v.push(0x81);
        v.push(u8::try_from(len).expect("fixture BER length fits one octet"));
    }
}
