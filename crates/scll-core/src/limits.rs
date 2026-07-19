//! Central capacity constants for the `no_std` + `heapless` build (PDD §2.2,
//! short-APDU-only). Every former `Vec`/`String` in the public surface is a
//! fixed-capacity `heapless` collection sized from one of these constants.
//!
//! Two tiers:
//!   * **Wire-level (normative).** Derived from ISO/GP limits — do NOT tune;
//!     changing them breaks spec conformance.
//!   * **Product/config.** Bounded by card *population*, not by any spec.
//!     Tune per target. Promote to const-generic parameters later if a single
//!     library build must serve cards of very different sizes.

// =========================================================================
// Wire-level (normative — do not tune)
// =========================================================================

/// Max AID length. RID (5) + PIX (≤11). ISO/IEC 7816-5; AID structure also
/// ISO/IEC 7816-4:2020 §8.
pub const AID_MAX: usize = 16;

/// Max short C-APDU on the wire: 4 header + 1 Lc + 255 data + 1 Le.
/// Extended APDUs are out of scope (PDD §2.2). ISO/IEC 7816-4:2020 §5.1.
pub const CAPDU_MAX: usize = 261;

/// Max short R-APDU: 256 response-data bytes (Le = `00`) + 2 SW.
/// ISO/IEC 7816-4:2020 §5.1.
pub const RAPDU_MAX: usize = 258;

/// ATR (contact) ≤ 33 B (ISO/IEC 7816-3 §8); ATS (contactless) ≤ 254 B via a
/// 1-byte length prefix (ISO/IEC 14443-4). 255 covers both.
pub const ATR_ATS_MAX: usize = 255;

/// Max Load File Data Block hash. SHA-512 = 64 B (largest of SHA-1/256/384/512
/// permitted by GPCS v2.3.1 §11.6; SHA-256 is the library default).
pub const HASH_MAX: usize = 64;

/// Max GET DATA response payload (bounded by the short-APDU response field).
/// Used for raw CRD `'66'`, CCI `'67'`, and key-template `'00E0'` captures.
pub const GETDATA_RAW_MAX: usize = 256;

/// Max INSTALL command data field (bounded by short Lc). GPCS v2.3.1 §11.5.
pub const INSTALL_PARAMS_MAX: usize = 255;

/// Issuer Identification Number object (`'0042'`). ISO/IEC 7812 — short BCD;
/// 16 B is safe headroom.
pub const IIN_MAX: usize = 16;

/// Card Image Number object (`'0045'`). Short; 16 B headroom.
pub const CIN_MAX: usize = 16;

/// Max plaintext key length (AES-256). Amendment D v1.1.2 §4.1. Sizes the
/// [`crate::backend::ExportedKey`] buffer and software-backend key storage.
pub const KEY_BYTES_MAX: usize = 32;

/// Encrypted key block value in a PUT KEY payload (the new key encrypted under
/// the DEK). AES-256 = 32 B (block-multiple, no extra pad); 3DES double = 16 B.
/// Amendment D v1.1.2 §4.1 / GPCS v2.3.1 §11.8. Returned by
/// `*_encrypt_put_key_payload`.
pub const ENC_KEY_BLOCK_MAX: usize = 32;

/// GP Key Check Value length. GPCS v2.3.1 §E / Amendment D §4.1.4.
pub const KCV_LEN: usize = 3;

/// SCP03 MAC chaining value / SCP02 ICV length (one AES/3DES block padded).
/// Backend-side only; listed here for the session-state sizing note.
pub const MAC_CHAIN_LEN: usize = 16;

/// Max SCP03 challenge / cryptogram / appended-MAC field length. 8 bytes in S8
/// mode, 16 bytes in S16 mode (Amendment D v1.2 §6.2.x). Bounds the
/// `heapless::Vec` returned by the cryptogram / pseudo-challenge backend
/// methods, and the parsed challenge/cryptogram fields in the IU response.
pub const SCP03_S16_MAX: usize = 16;

// =========================================================================
// Product / config (tune to the target card population)
// =========================================================================

/// Distinct SCP variants a card may advertise in CRD `'64'`.
pub const MAX_SCP_VARIANTS: usize = 8;

/// Keysets (by KVN) tracked in the ISD key inventory.
pub const MAX_KEYSETS: usize = 16;

/// Keys per keyset (KID slots; typically 3 — ENC/MAC/DEK).
pub const MAX_KEYS_PER_SET: usize = 16;

/// Cipher algorithms advertised in CCI `'A1'`.
pub const MAX_CIPHERS: usize = 16;

/// Raw privilege bytes captured from CCI (privileges are 3 B / 24 bits).
pub const MAX_PRIVILEGE_BYTES: usize = 8;

/// Security Domains held in a `CardInventory` snapshot.
pub const MAX_SDS: usize = 8;

/// Applet instances held in a `CardInventory` snapshot. Sized for a populated
/// `JCOP`-class card (the `gp --list` reference dump has ~30 ELFs + several
/// applets); a card reporting more yields `WarningKind::InventoryTruncated`
/// (PDD §5.12a), never an error.
pub const MAX_APPLETS: usize = 48;

/// Executable Load Files held in a `CardInventory` snapshot. Raised from 16 in
/// S7a: the reference `gp --list` dump alone has ~30 `PKG:` lines, so 16 would
/// always truncate a real card. Overflow ⇒ `WarningKind::InventoryTruncated`.
pub const MAX_ELFS: usize = 32;

/// Top-level `'E3'` registry entries decoded from **one** GET STATUS response
/// page by `parse_status_registry` (PDD §5.12a). A short-APDU page is ≤256 B and
/// the smallest `'E3'` entry is ~7 B, so ≤ ~36 fit; 64 is generous headroom.
/// The per-scope inventory caps (`MAX_SDS` / `MAX_APPLETS` / `MAX_ELFS`) bound
/// the *accumulated* result across pages; this only bounds a single page.
pub const MAX_REGISTRY_ENTRIES: usize = 64;

/// Maximum GET STATUS pages (`63 10` continuations) read per P1 scope before
/// `get_card_inventory` stops and flags `InventoryTruncated` (PDD §5.12a). A
/// guard against a card that loops on `63 10`; 16 pages × ~256 B comfortably
/// covers any short-APDU registry.
pub const MAX_STATUS_PAGES: usize = 16;

/// Raw-byte accumulator for one GET STATUS scope across all its `63 10`
/// continuations (PDD §5.12a; GPCS v2.3.1 §11.4 Table 11-38). The response is
/// chained at the **byte** level — a `'E3'` entry, or even a single nested
/// value inside it (e.g. a module AID), can be split exactly at the page
/// boundary — so each page's raw bytes are concatenated and the whole scope
/// is parsed once, rather than parsing every page independently. Sized as
/// `MAX_STATUS_PAGES × RAPDU_MAX` (16 × 258 = 4128 B), the worst case if every
/// page were maximally full; a card exceeding this is capped, same
/// "valid prefix, never an error" contract as the other inventory limits.
pub const MAX_STATUS_SCOPE_BYTES: usize = MAX_STATUS_PAGES * RAPDU_MAX;

/// Class (module) AIDs inside one ELF entry.
pub const MAX_MODULES_PER_ELF: usize = 16;

/// Objects reported removed by a cascade DELETE (`instances_removed`/`elfs_removed`).
pub const MAX_REMOVED_OBJECTS: usize = 32;

/// Imported package AIDs (dependencies) parsed from a CAP `Import.cap`.
pub const MAX_CAP_IMPORTS: usize = 16;

/// Applet class entries declared in one CAP `Applet.cap`.
pub const MAX_CAP_APPLETS: usize = 8;

/// Non-fatal warnings attached to any one report.
pub const MAX_WARNINGS: usize = 16;

/// Card quirk strings collected during discovery.
pub const MAX_QUIRKS: usize = 8;

/// Distinct GP key-type bytes in `ScllError::KeyTypeUnsupported.supported`.
pub const MAX_KEYTYPE_SUPPORTED: usize = 16;

/// Top-level BER-TLV objects returned by one `tlv::parse` call. Bounds the
/// parser's output list; denser input → `TlvError::TooMany` (no panic, §10.5).
/// A 256-byte response holds at most 128 minimal (2-byte) TLVs; 64 is generous
/// for real GP templates (`'66'`/`'67'`/`'E3'`/`'00E0'`).
pub const MAX_TLVS: usize = 64;

// =========================================================================
// Diagnostic string caps (heapless::String<N>)
// =========================================================================

/// Transport name (`"pcsc" | "jcsim" | "user"`). Could also be `&'static str`.
pub const TRANSPORT_NAME_MAX: usize = 16;

/// `Warning.detail` text.
pub const WARNING_DETAIL_MAX: usize = 128;

/// Free-form `Other(..)` detail (`CipherAlg` / `DiscoveryWarning` / `TransportError`).
/// Prefer typed variants over this where possible.
pub const OTHER_DETAIL_MAX: usize = 64;

// =========================================================================
// LOAD / CAP — streaming, STORED + DEFLATE (PDD §5.4a / §9)
// =========================================================================

/// LOAD command data payload per block, sized so the wrapped command always
/// fits a short APDU (Lc ≤ 255) under the most expensive secure-messaging mode
/// the backend can negotiate. Under C-DECRYPTION the chunk is first pad-`80`
/// (ISO 7816-4) padded up to the cipher block size (16 B SCP03 / 8 B SCP02) —
/// padding adds 1..block bytes, so an already block-aligned chunk grows by a
/// *whole* extra block — then a C-MAC is appended (8 B in SCP03-S8 / SCP02,
/// 16 B in SCP03-S16). Worst case (SCP03-S16): ceil16(chunk+1) + 16 ≤ 255 ⇒
/// chunk ≤ 223. The CAP parser yields the assembled LFDB (GPCS §C.2 order) in
/// chunks of this size; nothing holds the whole multi-KB block in RAM.
/// PDD §5.4a / §9; LOAD is GPCS v2.3.1 §11.6 (SCP03 wrap: Amendment D §6.2.3–6.2.4).
pub const LOAD_BLOCK_DATA: usize = 223;

/// DEFLATE sliding-window / dictionary size for inflating compressed CAP
/// components (RFC 1951 max back-reference distance = 32 KiB). The caller lends
/// a buffer of this size to `miniz_oxide` (alloc-free, `default-features =
/// false`); it doubles as the LZ77 dictionary, so no separate allocation is
/// needed. Must be a power of two. PDD §5.4a.
pub const INFLATE_WINDOW: usize = 32 * 1024;
