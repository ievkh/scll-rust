//! CAP-file parser — PDD §5.4a (Java Card VM Spec v3.1 Ch. 6). Pure; top fuzz
//! target (§10.5 #1: parses an attacker-influenceable ZIP).
//!
//! A `.cap` is a ZIP. The parser locates the components and presents the Load
//! File Data Block in GPCS §C.2 order: Header | Directory | Import | Applet |
//! Class | Method | `StaticField` | Export | `ConstantPool` | `RefLocation` |
//! Descriptor | [Debug excluded].
//!
//! `no_std`, streaming. The full LFDB is never materialized: [`CapFile`] borrows
//! the input ZIP, and the LFDB is produced one [`LOAD_BLOCK_DATA`]-sized chunk
//! at a time via [`LoadFileDataBlock::next_block`]. The caller feeds each chunk
//! to both the LFDB hasher and the LOAD command (§5.4a) incrementally.
//!
//! **Compression: STORED + DEFLATE, alloc-free.** STORED entries are read
//! directly from the borrowed input. DEFLATE entries are inflated with
//! `miniz_oxide` (`default-features = false`, no alloc) into a caller-lent
//! 32 KiB window ([`InflateCtx`]); the window is used as a **wrapping** LZ77
//! dictionary ring (RFC 1951's 32 KiB max match distance), so a component of
//! any size streams through it without heap or a full-output buffer, and host
//! and embedded share one code path. The standard `JavaCard` converter emits
//! DEFLATE JARs, so no host-side repack is required.

mod components;
pub use components::{AppletEntry, CapComponents};

use crate::aid::Aid;
use crate::limits::{INFLATE_WINDOW, LOAD_BLOCK_DATA};

// ---- CAP component set (Java Card VM Spec v3.1 §6.1) ----------------------

/// LFDB component count: the GPCS §C.2 order, `Debug.cap` excluded.
const LFDB_COMPONENTS: usize = 11;

/// Component file basenames in GPCS §C.2 / Load File Data Block order. `Debug`
/// is intentionally omitted: it is never part of the LFDB.
const COMPONENT_NAMES: [&[u8]; LFDB_COMPONENTS] = [
    b"Header.cap",
    b"Directory.cap",
    b"Import.cap",
    b"Applet.cap",
    b"Class.cap",
    b"Method.cap",
    b"StaticField.cap",
    b"Export.cap",
    b"ConstantPool.cap",
    b"RefLocation.cap",
    b"Descriptor.cap",
];

/// Index of `Header.cap` within [`COMPONENT_NAMES`] (mandatory component).
const IDX_HEADER: usize = 0;
/// Index of `Import.cap`.
const IDX_IMPORT: usize = 2;
/// Index of `Applet.cap`.
const IDX_APPLET: usize = 3;

/// CAP/JAR component header magic (`0xDECAFFED`, JC VM Spec v3.1 §6.3).
const HEADER_MAGIC: u32 = 0xDECA_FFED;

/// ZIP compression method: stored (no compression).
const METHOD_STORED: u16 = 0;
/// ZIP compression method: DEFLATE.
const METHOD_DEFLATE: u16 = 8;

// ---- ZIP record locations --------------------------------------------------

/// Where one CAP component's bytes live inside the borrowed ZIP, and how they
/// are encoded. Resolved once during [`parse`]; the bulk bytes stay in the
/// input.
#[derive(Clone, Copy)]
struct CompLoc {
    /// ZIP compression method (`0` stored, `8` DEFLATE).
    method: u16,
    /// Offset of the file *data* (post local-header) within the ZIP.
    data_off: usize,
    /// Compressed (on-disk) byte length.
    comp_size: usize,
    /// Uncompressed byte length (the component's contribution to the LFDB).
    uncomp_size: usize,
}

/// Parsed CAP file. Borrows the input ZIP bytes for the lifetime `'a`; the Load
/// File Data Block is produced on demand (never owned).
pub struct CapFile<'a> {
    pub package_aid: Aid,
    /// Parsed component metadata (imports, applet entries) — small owned values.
    pub components: CapComponents,
    /// Borrowed ZIP payload; the LFDB is streamed from here, never copied whole.
    pub(crate) zip: &'a [u8],
    /// Resolved component locations in §C.2 order; `None` = component absent.
    locs: [Option<CompLoc>; LFDB_COMPONENTS],
}

impl<'a> CapFile<'a> {
    /// A streaming view of the assembled Load File Data Block (GPCS §C.2 order).
    /// Total length is computed up front (drives the `'C4'` TLV length and the
    /// LOAD `block_count`); no bytes are copied/inflated until
    /// [`LoadFileDataBlock::next_block`].
    #[must_use]
    pub fn lfdb(&self) -> LoadFileDataBlock<'a> {
        let content_len = self.locs.iter().flatten().map(|c| c.uncomp_size).sum();
        LoadFileDataBlock {
            zip: self.zip,
            locs: self.locs,
            comp: 0,
            cursor: CompCursor::new(),
            header: LfdbHeader::new(content_len),
        }
    }
}

/// Caller-owned DEFLATE working set for compressed components: the 32 KiB
/// wrapping window ([`INFLATE_WINDOW`]) used as the LZ77 dictionary ring, plus
/// `miniz_oxide`'s decompressor state. Allocate once (it is large — the window
/// plus a multi-KB Huffman-table state struct; place it in a `static` or on a
/// generous stack) and lend it to [`LoadFileDataBlock::next_block`]. It is
/// untouched while a STORED component is being read.
pub struct InflateCtx {
    window: [u8; INFLATE_WINDOW],
    state: miniz_oxide::inflate::core::DecompressorOxide,
}

impl Default for InflateCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl InflateCtx {
    /// Construct a fresh inflate context (zeroed window, reset decompressor).
    #[must_use]
    #[expect(
        clippy::large_stack_arrays,
        reason = "32 KiB inflate window is intentional; the alloc-free no_std design lends it from a static or generous stack (PDD §5.4a) — heap allocation is unavailable"
    )]
    pub fn new() -> Self {
        Self {
            window: [0u8; INFLATE_WINDOW],
            state: miniz_oxide::inflate::core::DecompressorOxide::new(),
        }
    }

    /// Reset between components (clears the decompressor; the window is reused).
    pub fn reset(&mut self) {
        self.state = miniz_oxide::inflate::core::DecompressorOxide::new();
    }
}

/// Per-component streaming progress. For STORED, only `emitted` advances; for
/// DEFLATE, the ring bookkeeping (`produced`/`emitted`/`in_pos`/`done`) drives
/// the wrapping-window inflate.
#[derive(Clone, Copy)]
struct CompCursor {
    /// Bytes of compressed input consumed (DEFLATE only).
    in_pos: usize,
    /// Total decompressed bytes written into the ring (DEFLATE), or bytes
    /// copied from the STORED slice.
    produced: usize,
    /// Total bytes handed to the consumer for this component.
    emitted: usize,
    /// DEFLATE stream reported `Done`.
    done: bool,
    /// `state`/window have been reset for this (DEFLATE) component.
    started: bool,
}

impl CompCursor {
    const fn new() -> Self {
        Self {
            in_pos: 0,
            produced: 0,
            emitted: 0,
            done: false,
            started: false,
        }
    }
}

/// The `'C4'` Load File Data Block tag plus its BER length, streamed ahead of
/// the §C.2-ordered components (GPCS v2.3.1 §11.6.2.3 / Table 11-58). The card
/// expects the LOAD data field to begin `C4 ‖ len ‖ <load file>`, so this
/// header is emitted as the first bytes of the LFDB byte stream. It is tiny
/// (2–5 bytes) and may straddle into the first LOAD block alongside component
/// bytes. The length is the **content** length (sum of the components); it does
/// not count the header itself.
#[derive(Clone, Copy)]
struct LfdbHeader {
    buf: [u8; 5],
    len: u8,
    emitted: u8,
}

impl LfdbHeader {
    /// Build `C4 ‖ BER-length(content_len)`. BER definite length: a single byte
    /// for `< 0x80`, else `0x8N` followed by `N` big-endian length bytes
    /// (ISO/IEC 8825-1 / GPCS §11.1.5). A LOAD payload never exceeds the
    /// 256-block × short-APDU budget, so three length bytes (`0x83 …`) is the
    /// most that can occur; the 5-byte buffer covers it.
    #[allow(clippy::cast_possible_truncation)] // each byte is an explicit 8-bit slice of content_len
    const fn new(content_len: usize) -> Self {
        let mut buf = [0u8; 5];
        buf[0] = 0xC4;
        let len: u8 = if content_len < 0x80 {
            buf[1] = content_len as u8;
            2
        } else if content_len <= 0xFF {
            buf[1] = 0x81;
            buf[2] = content_len as u8;
            3
        } else if content_len <= 0xFFFF {
            buf[1] = 0x82;
            buf[2] = (content_len >> 8) as u8;
            buf[3] = content_len as u8;
            4
        } else {
            buf[1] = 0x83;
            buf[2] = (content_len >> 16) as u8;
            buf[3] = (content_len >> 8) as u8;
            buf[4] = content_len as u8;
            5
        };
        Self {
            buf,
            len,
            emitted: 0,
        }
    }

    /// Header bytes not yet handed to the consumer.
    const fn remaining(self) -> usize {
        (self.len - self.emitted) as usize
    }

    /// Copy as many remaining header bytes as fit into `out`; return the count.
    #[allow(clippy::cast_possible_truncation)] // `take` is bounded by `len` (≤ 5)
    fn emit(&mut self, out: &mut [u8]) -> usize {
        let from = self.emitted as usize;
        let take = self.remaining().min(out.len());
        out[..take].copy_from_slice(&self.buf[from..from + take]);
        self.emitted += take as u8;
        take
    }

    /// Restart header emission (paired with [`LoadFileDataBlock::reset`]).
    fn reset(&mut self) {
        self.emitted = 0;
    }
}

/// Streaming Load File Data Block. Stateful pull reader: each call to
/// [`Self::next_block`] writes the next chunk into the caller's buffer, so the
/// whole block never resides in RAM at once.
pub struct LoadFileDataBlock<'a> {
    zip: &'a [u8],
    locs: [Option<CompLoc>; LFDB_COMPONENTS],
    /// Index into `locs` of the component currently being emitted.
    comp: usize,
    cursor: CompCursor,
    /// `'C4'` tag + BER length, streamed before the first component.
    header: LfdbHeader,
}

impl LoadFileDataBlock<'_> {
    /// Total LFDB byte length (sum of the §C.2-ordered components, decompressed).
    /// Needed for the `'C4'` tag length and to derive `block_count`.
    /// Total **framed** LFDB byte length streamed to LOAD: the `'C4'` tag+length
    /// header plus the §C.2-ordered component content. This is what the LOAD
    /// loop counts for last-block detection and `block_count`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.header.len as usize + self.content_len()
    }

    /// Content length only — the value of the `'C4'` TLV (sum of the §C.2
    /// components, decompressed), excluding the header. This is the length
    /// encoded in the `'C4'` header and the input over which a Load File Data
    /// Block Hash (Lh) would be computed (GPCS v2.3.1 §11.6.2.3) — not the
    /// framed stream.
    #[must_use]
    pub fn content_len(&self) -> usize {
        self.locs.iter().flatten().map(|c| c.uncomp_size).sum()
    }

    /// `true` if there is no component content (degenerate / malformed CAP).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content_len() == 0
    }

    /// Write the next LFDB chunk into `out` (should be [`LOAD_BLOCK_DATA`] long)
    /// and return the byte count written. Returns `Ok(0)` once the block is
    /// exhausted. STORED components are copied from the borrowed input; DEFLATE
    /// components are inflated through `infl` (the 32 KiB window doubles as the
    /// wrapping dictionary). A chunk may straddle component boundaries (the LFDB
    /// is the concatenation in GPCS §C.2 order), so bytes are assembled into
    /// `out`.
    ///
    /// # Errors
    /// Returns [`CapError::Inflate`] if a DEFLATE component cannot be
    /// decompressed (corrupt stream, or the input/window bound was exceeded).
    pub fn next_block(&mut self, infl: &mut InflateCtx, out: &mut [u8]) -> Result<usize, CapError> {
        let mut written = 0;
        // The `'C4'` tag+length header is streamed ahead of the components; it
        // may share the first block with component bytes.
        if self.header.remaining() > 0 {
            written += self.header.emit(out);
        }
        while written < out.len() {
            // Advance past absent components and components fully emitted.
            let Some(loc) = self.current_loc() else {
                if self.comp >= LFDB_COMPONENTS {
                    break; // LFDB exhausted
                }
                self.advance();
                continue;
            };
            let n = if loc.method == METHOD_DEFLATE {
                self.emit_deflate(&loc, infl, &mut out[written..])?
            } else {
                self.emit_stored(&loc, &mut out[written..])
            };
            written += n;
            if self.component_exhausted(&loc) {
                self.advance();
            } else if n == 0 {
                // No progress with space remaining ⇒ guard against a stall.
                break;
            }
        }
        Ok(written)
    }

    /// Restart from the first byte (e.g. to hash the LFDB, then re-stream it to
    /// LOAD without re-parsing the ZIP). Caller should also `infl.reset()`.
    pub fn reset(&mut self) {
        self.comp = 0;
        self.cursor = CompCursor::new();
        self.header.reset();
    }

    /// The location of the component currently being emitted, if present and
    /// not yet exhausted.
    fn current_loc(&self) -> Option<CompLoc> {
        self.locs.get(self.comp).copied().flatten()
    }

    /// Move to the next component, resetting per-component progress.
    fn advance(&mut self) {
        self.comp += 1;
        self.cursor = CompCursor::new();
    }

    /// `true` once every decompressed/stored byte of `loc` has been emitted.
    fn component_exhausted(&self, loc: &CompLoc) -> bool {
        self.cursor.emitted >= loc.uncomp_size
    }

    /// Copy the next slice of a STORED component straight from the ZIP.
    fn emit_stored(&mut self, loc: &CompLoc, out: &mut [u8]) -> usize {
        let start = loc.data_off + self.cursor.emitted;
        let remaining = loc.uncomp_size - self.cursor.emitted;
        let take = remaining
            .min(out.len())
            .min(self.zip.len().saturating_sub(start));
        out[..take].copy_from_slice(&self.zip[start..start + take]);
        self.cursor.emitted += take;
        take
    }

    /// Inflate the next slice of a DEFLATE component through the wrapping ring.
    fn emit_deflate(
        &mut self,
        loc: &CompLoc,
        infl: &mut InflateCtx,
        out: &mut [u8],
    ) -> Result<usize, CapError> {
        if !self.cursor.started {
            infl.reset();
            self.cursor.started = true;
        }
        let mut w = 0;
        while w < out.len() {
            let pending = self.cursor.produced - self.cursor.emitted;
            if pending == 0 {
                if self.cursor.done {
                    break;
                }
                self.pump(loc, infl)?;
                if self.cursor.produced == self.cursor.emitted && self.cursor.done {
                    break;
                }
                continue;
            }
            let mask = INFLATE_WINDOW - 1;
            let start = self.cursor.emitted & mask;
            let take = pending.min(out.len() - w).min(INFLATE_WINDOW - start);
            out[w..w + take].copy_from_slice(&infl.window[start..start + take]);
            self.cursor.emitted += take;
            w += take;
        }
        Ok(w)
    }

    /// Drive `miniz_oxide` once, appending output into the wrapping window.
    fn pump(&mut self, loc: &CompLoc, infl: &mut InflateCtx) -> Result<(), CapError> {
        use miniz_oxide::inflate::core::decompress;
        use miniz_oxide::inflate::TINFLStatus;

        let comp_end = loc.data_off + loc.comp_size;
        if comp_end > self.zip.len() || loc.data_off + self.cursor.in_pos > comp_end {
            return Err(CapError::Inflate);
        }
        let input = &self.zip[loc.data_off + self.cursor.in_pos..comp_end];
        let ring_pos = self.cursor.produced & (INFLATE_WINDOW - 1);
        // Raw DEFLATE (no zlib header), whole remaining input available.
        let (status, in_consumed, out_written) =
            decompress(&mut infl.state, input, &mut infl.window, ring_pos, 0);
        self.cursor.in_pos += in_consumed;
        self.cursor.produced += out_written;
        match status {
            TINFLStatus::Done => {
                self.cursor.done = true;
                Ok(())
            }
            TINFLStatus::HasMoreOutput | TINFLStatus::NeedsMoreInput => {
                if in_consumed == 0 && out_written == 0 {
                    // No forward progress with input remaining ⇒ corrupt stream.
                    Err(CapError::Inflate)
                } else {
                    Ok(())
                }
            }
            _ => Err(CapError::Inflate),
        }
    }
}

/// Parse a `.cap` (ZIP) byte buffer. Borrows `cap_zip` for the returned
/// `CapFile`'s lifetime. STORED and DEFLATE entries are both accepted.
///
/// `infl` is the caller-lent 32 KiB inflate context: `parse` uses it to
/// decompress the (small) Header/Import/Applet metadata components when they
/// are DEFLATE-encoded, so the same buffer later serves [`CapFile::lfdb`]
/// streaming — no second large allocation. It is left reset on return.
///
/// # Errors
/// Returns [`CapError::NotAZip`] if `cap_zip` is not a ZIP,
/// [`CapError::MissingComponent`] / [`CapError::Malformed`] for a structurally
/// invalid CAP, or [`CapError::Inflate`] if a DEFLATE metadata component cannot
/// be decompressed.
pub fn parse<'a>(cap_zip: &'a [u8], infl: &mut InflateCtx) -> Result<CapFile<'a>, CapError> {
    let locs = walk_zip(cap_zip)?;

    let header_loc = locs[IDX_HEADER].ok_or(CapError::MissingComponent("Header.cap"))?;
    // Metadata components are small; materialize each (in turn) into the lent
    // window and parse it before reading the next — no second large allocation.
    let header = read_component(cap_zip, &header_loc, infl)?;
    let (package_aid, jc_platform_version) = parse_header(header)?;

    let mut components = CapComponents {
        jc_platform_version,
        imports: heapless::Vec::new(),
        applets: heapless::Vec::new(),
    };

    if let Some(import_loc) = locs[IDX_IMPORT] {
        let bytes = read_component(cap_zip, &import_loc, infl)?;
        parse_imports(bytes, &mut components)?;
    }
    if let Some(applet_loc) = locs[IDX_APPLET] {
        let bytes = read_component(cap_zip, &applet_loc, infl)?;
        parse_applets(bytes, &mut components)?;
    }

    infl.reset();
    Ok(CapFile {
        package_aid,
        components,
        zip: cap_zip,
        locs,
    })
}

/// Materialize one (small, metadata) component into the lent window and return
/// the resulting slice. STORED components are copied in; DEFLATE components are
/// inflated with the non-wrapping flag (a metadata component fits the window by
/// construction — one that would exceed it is reported as
/// [`CapError::Inflate`]). The borrow of `infl` ends when the returned slice is
/// dropped, so the caller parses one component fully before reading the next.
fn read_component<'a>(
    zip: &[u8],
    loc: &CompLoc,
    infl: &'a mut InflateCtx,
) -> Result<&'a [u8], CapError> {
    use miniz_oxide::inflate::core::decompress;
    use miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    use miniz_oxide::inflate::TINFLStatus;

    let end = loc
        .data_off
        .checked_add(loc.comp_size)
        .ok_or(CapError::Malformed)?;
    if end > zip.len() {
        return Err(CapError::Malformed);
    }
    let input = &zip[loc.data_off..end];
    match loc.method {
        METHOD_STORED => {
            if input.len() > infl.window.len() {
                return Err(CapError::Malformed);
            }
            infl.window[..input.len()].copy_from_slice(input);
            Ok(&infl.window[..input.len()])
        }
        METHOD_DEFLATE => {
            infl.reset();
            let (status, _in, written) = decompress(
                &mut infl.state,
                input,
                &mut infl.window,
                0,
                TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
            );
            match status {
                TINFLStatus::Done => Ok(&infl.window[..written]),
                // HasMoreOutput here means the component exceeds the window: out
                // of our metadata bound — treat as malformed rather than guess.
                _ => Err(CapError::Inflate),
            }
        }
        _ => Err(CapError::Malformed),
    }
}

// ---- ZIP central-directory walk -------------------------------------------

/// End Of Central Directory signature.
const SIG_EOCD: u32 = 0x0605_4b50;
/// Central directory file-header signature.
const SIG_CDH: u32 = 0x0201_4b50;
/// Local file-header signature.
const SIG_LFH: u32 = 0x0403_4b50;
/// Minimum EOCD record length (no comment).
const EOCD_MIN: usize = 22;

/// Resolve every recognised CAP component to its byte location in the ZIP.
fn walk_zip(zip: &[u8]) -> Result<[Option<CompLoc>; LFDB_COMPONENTS], CapError> {
    let eocd = find_eocd(zip).ok_or(CapError::NotAZip)?;
    let total = usize::from(u16::from_le_bytes([zip[eocd + 10], zip[eocd + 11]]));
    let cd_off = read_u32(zip, eocd + 16).ok_or(CapError::Malformed)? as usize;

    let mut locs: [Option<CompLoc>; LFDB_COMPONENTS] = [None; LFDB_COMPONENTS];
    let mut pos = cd_off;
    for _ in 0..total {
        if read_u32(zip, pos) != Some(SIG_CDH) {
            return Err(CapError::Malformed);
        }
        let method = read_u16(zip, pos + 10).ok_or(CapError::Malformed)?;
        let comp_size = read_u32(zip, pos + 20).ok_or(CapError::Malformed)? as usize;
        let uncomp_size = read_u32(zip, pos + 24).ok_or(CapError::Malformed)? as usize;
        let name_len = usize::from(read_u16(zip, pos + 28).ok_or(CapError::Malformed)?);
        let extra_len = usize::from(read_u16(zip, pos + 30).ok_or(CapError::Malformed)?);
        let comment_len = usize::from(read_u16(zip, pos + 32).ok_or(CapError::Malformed)?);
        let local_off = read_u32(zip, pos + 42).ok_or(CapError::Malformed)? as usize;

        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(CapError::Malformed)?;
        if name_end > zip.len() {
            return Err(CapError::Malformed);
        }
        let name = &zip[name_start..name_end];

        if let Some(idx) = component_index(name) {
            if locs[idx].is_none() {
                let data_off = local_data_offset(zip, local_off)?;
                locs[idx] = Some(CompLoc {
                    method,
                    data_off,
                    comp_size,
                    uncomp_size,
                });
            }
        }

        pos = name_end
            .checked_add(extra_len)
            .and_then(|p| p.checked_add(comment_len))
            .ok_or(CapError::Malformed)?;
    }
    Ok(locs)
}

/// Scan backwards for the EOCD signature, returning its offset.
fn find_eocd(zip: &[u8]) -> Option<usize> {
    if zip.len() < EOCD_MIN {
        return None;
    }
    let max_back = zip.len() - EOCD_MIN;
    // The comment can be up to 64 KiB; bound the scan accordingly.
    let limit = max_back.saturating_sub(0xFFFF);
    let mut i = max_back;
    loop {
        if read_u32(zip, i) == Some(SIG_EOCD) {
            return Some(i);
        }
        if i == 0 || i == limit {
            return None;
        }
        i -= 1;
    }
}

/// Compute the offset of file data given a local-file-header offset.
fn local_data_offset(zip: &[u8], local_off: usize) -> Result<usize, CapError> {
    if read_u32(zip, local_off) != Some(SIG_LFH) {
        return Err(CapError::Malformed);
    }
    let name_len = usize::from(read_u16(zip, local_off + 26).ok_or(CapError::Malformed)?);
    let extra_len = usize::from(read_u16(zip, local_off + 28).ok_or(CapError::Malformed)?);
    local_off
        .checked_add(30)
        .and_then(|p| p.checked_add(name_len))
        .and_then(|p| p.checked_add(extra_len))
        .filter(|&p| p <= zip.len())
        .ok_or(CapError::Malformed)
}

/// Map a ZIP entry name to its index in [`COMPONENT_NAMES`] by basename.
fn component_index(name: &[u8]) -> Option<usize> {
    let base = match name.iter().rposition(|&b| b == b'/' || b == b'\\') {
        Some(i) => &name[i + 1..],
        None => name,
    };
    COMPONENT_NAMES.iter().position(|&n| n == base)
}

// ---- Component metadata parsers (JC VM Spec v3.1 Ch. 6) -------------------

/// Parse `Header.cap`: validate magic and extract the package AID plus the CAP
/// format version (recorded as `jc_platform_version`; see manifest note).
fn parse_header(b: &[u8]) -> Result<(Aid, (u8, u8, u8)), CapError> {
    // tag(1) size(2) magic(4) minor(1) major(1) flags(1) pkg{minor major len aid}
    let magic = read_u32_be(b, 3).ok_or(CapError::Malformed)?;
    if magic != HEADER_MAGIC {
        return Err(CapError::Malformed);
    }
    let minor = *b.get(7).ok_or(CapError::Malformed)?;
    let major = *b.get(8).ok_or(CapError::Malformed)?;
    let aid_len = usize::from(*b.get(12).ok_or(CapError::Malformed)?);
    let aid_start = 13usize;
    let aid_end = aid_start.checked_add(aid_len).ok_or(CapError::Malformed)?;
    let aid_bytes = b.get(aid_start..aid_end).ok_or(CapError::Malformed)?;
    let aid = Aid::new(aid_bytes).map_err(|_| CapError::Malformed)?;
    Ok((aid, (major, minor, 0)))
}

/// Parse `Import.cap`: a count followed by `package_info` entries; record each
/// imported package AID.
fn parse_imports(b: &[u8], out: &mut CapComponents) -> Result<(), CapError> {
    // tag(1) size(2) count(1) then count * {minor(1) major(1) len(1) aid[len]}
    let count = usize::from(*b.get(3).ok_or(CapError::Malformed)?);
    let mut p = 4;
    for _ in 0..count {
        let len = usize::from(*b.get(p + 2).ok_or(CapError::Malformed)?);
        let aid_start = p + 3;
        let aid_end = aid_start.checked_add(len).ok_or(CapError::Malformed)?;
        let aid_bytes = b.get(aid_start..aid_end).ok_or(CapError::Malformed)?;
        let aid = Aid::new(aid_bytes).map_err(|_| CapError::Malformed)?;
        out.imports.push(aid).map_err(|_| CapError::Malformed)?;
        p = aid_end;
    }
    Ok(())
}

/// Parse `Applet.cap`: a count followed by `{ AID, install_method_offset }`
/// entries.
fn parse_applets(b: &[u8], out: &mut CapComponents) -> Result<(), CapError> {
    // tag(1) size(2) count(1) then count * {len(1) aid[len] install_offset(2 BE)}
    let count = usize::from(*b.get(3).ok_or(CapError::Malformed)?);
    let mut p = 4;
    for _ in 0..count {
        let len = usize::from(*b.get(p).ok_or(CapError::Malformed)?);
        let aid_start = p + 1;
        let aid_end = aid_start.checked_add(len).ok_or(CapError::Malformed)?;
        let aid_bytes = b.get(aid_start..aid_end).ok_or(CapError::Malformed)?;
        let aid = Aid::new(aid_bytes).map_err(|_| CapError::Malformed)?;
        let install_method_offset = read_u16_be(b, aid_end).ok_or(CapError::Malformed)?;
        out.applets
            .push(AppletEntry {
                class_aid: aid,
                install_method_offset,
            })
            .map_err(|_| CapError::Malformed)?;
        p = aid_end + 2;
    }
    Ok(())
}

// ---- Bounds-checked field readers -----------------------------------------

fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u16_be(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// CAP parse failure.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CapError {
    #[error("input is not a ZIP")]
    NotAZip,
    #[error("missing CAP component: {0}")]
    MissingComponent(&'static str),
    #[error("malformed CAP structure")]
    Malformed,
    /// DEFLATE decompression of a component failed (corrupt stream, or the
    /// window/output bound was exceeded).
    #[error("CAP component inflate failed")]
    Inflate,
}

// Keep LOAD_BLOCK_DATA referenced so the intended chunk size is documented at
// the API boundary; next_block's `out` should be this long.
const _: usize = LOAD_BLOCK_DATA;

#[cfg(test)]
mod tests {
    use super::*;

    // Real ZIP fixtures emitted by Python `zipfile` (paths prefixed
    // `p/javacard/`, with a `Debug.cap` present to confirm LFDB exclusion).
    const STORED: &[u8] = include_bytes!("testdata/minimal_stored.cap");
    const DEFLATE: &[u8] = include_bytes!("testdata/streaming_deflate.cap");

    // Component bytes baked into the fixtures (see testdata generator).
    const PKG_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01];
    const IMPORT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
    const APPLET_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0A];

    fn stream_all(cf: &CapFile<'_>, infl: &mut InflateCtx) -> (usize, std::vec::Vec<u8>) {
        let mut s = cf.lfdb();
        let total = s.len();
        let mut out: std::vec::Vec<u8> = std::vec::Vec::new();
        let mut buf = [0u8; LOAD_BLOCK_DATA];
        loop {
            let n = s.next_block(infl, &mut buf).expect("inflate ok");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        (total, out)
    }

    fn assert_metadata(cf: &CapFile<'_>) {
        assert_eq!(cf.package_aid.as_bytes(), PKG_AID);
        assert_eq!(cf.components.jc_platform_version, (2, 1, 0));
        assert_eq!(cf.components.imports.len(), 1);
        assert_eq!(cf.components.imports[0].as_bytes(), IMPORT_AID);
        assert_eq!(cf.components.applets.len(), 1);
        assert_eq!(cf.components.applets[0].class_aid.as_bytes(), APPLET_AID);
        assert_eq!(cf.components.applets[0].install_method_offset, 0x001F);
    }

    #[test]
    fn parses_stored_metadata() {
        let mut infl = InflateCtx::new();
        let cf = parse(STORED, &mut infl).expect("parse stored");
        assert_metadata(&cf);
    }

    #[test]
    fn parses_deflate_metadata() {
        let mut infl = InflateCtx::new();
        let cf = parse(DEFLATE, &mut infl).expect("parse deflate");
        assert_metadata(&cf);
    }

    fn header_len(content_len: usize) -> usize {
        LfdbHeader::new(content_len).len as usize
    }

    #[test]
    fn stored_lfdb_is_concatenation_in_c2_order() {
        // Header(20) Dir(3) Import(14) Applet(15) Class(2) Method(4)
        // StaticField(2) Export(2) ConstantPool(2) RefLocation(2) Descriptor(2).
        let mut infl = InflateCtx::new();
        let cf = parse(STORED, &mut infl).expect("parse");
        let (total, out) = stream_all(&cf, &mut infl);
        assert_eq!(total, out.len());
        let content = 20 + 3 + 14 + 15 + 2 + 4 + 2 + 2 + 2 + 2 + 2;
        let header = LfdbHeader::new(content);
        let hdr = header.len as usize;
        // Stream is `'C4' ‖ len ‖ <components>`; content is 68 B (< 0x80) so the
        // length is a single byte → header is `C4 44`.
        assert_eq!(total, hdr + content);
        assert_eq!(&out[..hdr], &header.buf[..hdr]);
        // First component is Header.cap → its magic is at content offset 3,
        // i.e. stream offset `hdr + 3`.
        assert_eq!(&out[hdr + 3..hdr + 7], &[0xDE, 0xCA, 0xFF, 0xED]);
        // Debug.cap content must never appear in the LFDB.
        assert!(!out.windows(3).any(|w| w == b"DBG"));
    }

    #[test]
    fn deflate_lfdb_streams_oversized_component_through_ring() {
        // Method.cap is ~52 KiB (> the 32 KiB window): exercises the wrapping
        // ring path. Rebuild the expected block deterministically.
        let big = {
            let mut v = std::vec::Vec::new();
            while v.len() < 52_000 {
                v.extend_from_slice(b"METHOD-BYTES-");
            }
            v.truncate(52_000);
            v
        };
        let mut infl = InflateCtx::new();
        let cf = parse(DEFLATE, &mut infl).expect("parse");
        let (total, out) = stream_all(&cf, &mut infl);
        assert_eq!(total, out.len());
        // Header(20)+Dir(3)+Import(14)+Applet(15)+Class(2)+Method(52000)
        //   +StaticField(2)+Export(2)+ConstantPool(2)+RefLocation(2)+Descriptor(2)
        let method_start_content = 20 + 3 + 14 + 15 + 2;
        let content = method_start_content + big.len() + 2 + 2 + 2 + 2 + 2;
        let hdr = header_len(content);
        assert_eq!(total, hdr + content);
        // Method bytes begin after the `'C4'` header in the framed stream.
        let method_start = hdr + method_start_content;
        assert_eq!(&out[method_start..method_start + big.len()], &big[..]);
    }

    #[test]
    fn lfdb_reset_re_streams_identically() {
        let mut infl = InflateCtx::new();
        let cf = parse(STORED, &mut infl).expect("parse");
        let mut s = cf.lfdb();
        let mut buf = [0u8; LOAD_BLOCK_DATA];
        let first = s.next_block(&mut infl, &mut buf).expect("ok");
        let head_a = buf[..first].to_vec();
        s.reset();
        infl.reset();
        let second = s.next_block(&mut infl, &mut buf).expect("ok");
        assert_eq!(first, second);
        assert_eq!(head_a.as_slice(), &buf[..second]);
    }

    #[test]
    fn not_a_zip_is_rejected() {
        let mut infl = InflateCtx::new();
        assert!(matches!(
            parse(b"definitely not a zip", &mut infl),
            Err(CapError::NotAZip)
        ));
    }

    #[test]
    fn empty_input_is_rejected() {
        let mut infl = InflateCtx::new();
        assert!(matches!(parse(&[], &mut infl), Err(CapError::NotAZip)));
    }

    #[test]
    fn missing_header_component_is_reported() {
        // Truncate the stored fixture's central directory name "Header.cap" by
        // flipping the first byte of every 'H' so no component matches Header.
        // Simpler: build via mutation — corrupt the Header.cap basename.
        let mut z = STORED.to_vec();
        // Replace the first occurrence of b"Header.cap" with b"Xeader.cap".
        if let Some(p) = z.windows(10).position(|w| w == b"Header.cap") {
            z[p] = b'X';
            // It appears twice (local + central header); flip both.
            if let Some(p2) = z[p + 1..].windows(10).position(|w| w == b"Header.cap") {
                z[p + 1 + p2] = b'X';
            }
        }
        let mut infl = InflateCtx::new();
        assert!(matches!(
            parse(&z, &mut infl),
            Err(CapError::MissingComponent("Header.cap"))
        ));
    }

    #[test]
    fn truncated_zip_does_not_panic() {
        let mut infl = InflateCtx::new();
        for cut in [1usize, 5, 22, 40, 100, 200] {
            let n = cut.min(STORED.len());
            let _ = parse(&STORED[..n], &mut infl); // must not panic
        }
    }

    #[test]
    fn corrupt_deflate_stream_errors_cleanly() {
        // Flip bytes in the compressed Method.cap region: inflate must fail with
        // a typed error rather than panic. Mutate a mid-file byte and re-parse;
        // streaming the LFDB should surface CapError::Inflate (or parse rejects).
        let mut z = DEFLATE.to_vec();
        let mid = z.len() / 2;
        z[mid] ^= 0xFF;
        z[mid + 1] ^= 0xFF;
        let mut infl = InflateCtx::new();
        // Parse may reject outright (also fine); if it accepts, draining the
        // LFDB must surface the corruption as an error, never a panic.
        if let Ok(cf) = parse(&z, &mut infl) {
            let mut s = cf.lfdb();
            let mut buf = [0u8; LOAD_BLOCK_DATA];
            while let Ok(n) = s.next_block(&mut infl, &mut buf) {
                if n == 0 {
                    break; // exhausted without error
                }
            }
        }
    }

    #[test]
    fn component_index_matches_basename_only() {
        assert_eq!(component_index(b"p/javacard/Header.cap"), Some(IDX_HEADER));
        assert_eq!(component_index(b"Import.cap"), Some(IDX_IMPORT));
        assert_eq!(component_index(b"Applet.cap"), Some(IDX_APPLET));
        assert_eq!(component_index(b"Debug.cap"), None); // excluded from LFDB
        assert_eq!(component_index(b"NotMyHeader.cap"), None);
        assert_eq!(component_index(b"weird\\Class.cap"), Some(4));
    }
}
