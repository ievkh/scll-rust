//! INSTALL (CLA 84, INS E6) — PDD §5.4/§5.4a/§5.6/§5.7, GPCS §11.5.
//!
//! P1 variants: `0x02` for Load (§11.5.2.1) and `0x0C` Install + Make
//! Selectable (§11.5.2.3). Length-prefixed fields:
//! `Lf|ELF_AID Lm|Module_AID La|Instance_AID Lp|Privileges Li|Params Lt|Token`.
//! `'C9'` install params mandatory even if empty (`C9 00`) — supplied by the
//! caller in `install_params` (see `install_for_install_make_selectable`).

use crate::command::{build, push_lv, BuildError, Capdu};

/// Encoding length for the GP **Privileges** field (GPCS v2.3.1 §11.1.2,
/// Tables 11-7..11-9). The field may legally be 1 byte (legacy / pre-2.2) or
/// 3 bytes (the 2.2+ extended encoding); byte 1 carries the core privileges
/// (Security Domain `0x80`, Card Lock, Card Terminate, …) and bytes 2–3 carry
/// the 2.2+ extended privileges (Trusted Path `0x80` in byte 2, …).
///
/// When an extended (byte 2/3) bit is actually set, the 3-byte form is
/// mandatory and this selector is ignored. When bytes 2–3 are zero, the two
/// forms are value-equivalent *per the spec*, but real implementations differ:
///
/// - `Canonical` (3-byte) is the spec-canonical form and the safe default. The
///   Oracle JCDK simulator requires it: given only the 1-byte form it does not
///   treat bytes 2–3 as zero and ends up reporting an unintended privilege
///   (e.g. Trusted Path) for the created SD.
/// - `Jcop1Byte` collapses to 1 byte. NXP JCOP 4 P71 / J3R150 requires this:
///   it rejects `Lp = 03` for a privilege that fits in byte 1 and accepts only
///   `Lp = 01` (e.g. `01 80` for an SSD).
///
/// Selection is a per-card property; discovery sets it, the workflow passes it
/// through. Default to `Canonical` unless a JCOP-P71 quirk is detected.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum PrivLen {
    /// Always emit the full 3-byte Privileges field (spec-canonical; jcsim).
    #[default]
    Canonical,
    /// Collapse to the 1-byte form when bytes 2–3 are zero (NXP JCOP 4 P71).
    Jcop1Byte,
}

/// Push the GP **Privileges** field at the length selected by `enc`.
///
/// If any extended (byte 2/3) bit is set, the full 3-byte form is emitted
/// regardless of `enc` (truncating it would silently drop privileges — GPCS
/// v2.3.1 §11.1.2). Otherwise `enc` chooses between the 3-byte canonical form
/// (`PrivLen::Canonical`) and the 1-byte legacy form (`PrivLen::Jcop1Byte`).
fn push_privileges(data: &mut Capdu, privileges: [u8; 3], enc: PrivLen) -> Result<(), BuildError> {
    let has_extended = privileges[1] != 0 || privileges[2] != 0;
    let len = if has_extended {
        3
    } else {
        match enc {
            PrivLen::Canonical => 3,
            PrivLen::Jcop1Byte => 1,
        }
    };
    push_lv(data, &privileges[..len])
}

/// INSTALL [for Load] (P1 `0x02`, GPCS §11.5.2.1).
///
/// Data = `Lp‖Package_AID  Ls‖Target_SD_AID  Lh‖LFDB_Hash  Lr=00  Lt=00`
/// (Load Parameters and Load Token empty under AM). `Le=00`.
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn install_for_load(
    package_aid: &[u8],
    target_sd_aid: &[u8],
    lfdb_hash: &[u8],
) -> Result<Capdu, BuildError> {
    let mut data = Capdu::new();
    push_lv(&mut data, package_aid)?;
    push_lv(&mut data, target_sd_aid)?;
    push_lv(&mut data, lfdb_hash)?;
    push_lv(&mut data, &[])?; // Load Parameters: empty (Lr = 00)
    push_lv(&mut data, &[])?; // Load Token: empty under AM (Lt = 00)
    build(0x84, 0xE6, 0x02, 0x00, &data, true)
}

/// INSTALL [for Install and Make Selectable] (P1 `0x0C`). Shared by §5.4 and §5.7.
///
/// Data = `Lf‖ELF_AID  Lm‖Module_AID  La‖Instance_AID  Lp‖Privileges(1|3)
/// Li‖Install_Params  Lt=00`. `priv_len` selects the Privileges encoding
/// length (see [`PrivLen`]); an extended 2.2+ privilege bit always forces the
/// 3-byte form. `install_params` is the **complete** Install Params field
/// value and must already contain the mandatory `'C9'` TLV (e.g. `C9 00` when
/// empty), optionally followed by an `'EF'` system-params TLV (§11.5.2.3.7);
/// the builder only length-prefixes it. `Le=00`.
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn install_for_install_make_selectable(
    elf_aid: &[u8],
    module_aid: &[u8],
    instance_aid: &[u8],
    privileges: [u8; 3],
    priv_len: PrivLen,
    install_params: &[u8],
) -> Result<Capdu, BuildError> {
    let mut data = Capdu::new();
    push_lv(&mut data, elf_aid)?;
    push_lv(&mut data, module_aid)?;
    push_lv(&mut data, instance_aid)?;
    push_privileges(&mut data, privileges, priv_len)?;
    push_lv(&mut data, install_params)?;
    push_lv(&mut data, &[])?; // Install Token: empty under AM (Lt = 00)
    build(0x84, 0xE6, 0x0C, 0x00, &data, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    #[test]
    fn for_load_lays_out_all_five_fields() {
        let pkg = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let sd = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let hash = [0x11, 0x22, 0x33, 0x44];
        let apdu = install_for_load(&pkg, &sd, &hash).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([
                0x84, 0xE6, 0x02, 0x00, 0x13, // Lc = 19
                0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, // Lp | Package_AID
                0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, // Ls | Target_SD_AID
                0x04, 0x11, 0x22, 0x33, 0x44, // Lh | LFDB hash
                0x00, // Lr (load params empty)
                0x00, // Lt (load token empty)
                0x00, // Le
            ])
        );
    }

    #[test]
    fn for_load_carries_full_sha256_hash_length() {
        let aid = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let hash = [0x00u8; 32];
        let apdu = install_for_load(&aid, &aid, &hash).unwrap();
        // After Lp(1)|pkg(5) Ls(1)|sd(5), the Lh byte must be 0x20 (32).
        assert_eq!(apdu[5 + 6 + 6], 0x20);
    }

    #[test]
    fn install_make_selectable_canonical_emits_three_byte_privileges() {
        // Default / spec-canonical form: even an SD-only privilege is sent as
        // the full 3-byte field `03 80 00 00` (GPCS v2.3.1 §11.1.2). This is
        // the form the Oracle JCDK simulator requires.
        let elf = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let module = [0xB0, 0x00, 0x00, 0x02, 0x52];
        let instance = [0xC0, 0x00, 0x00, 0x03, 0x53];
        let privileges = [0x80, 0x00, 0x00]; // SD only
        let params = [0xC9, 0x00]; // mandatory empty 'C9'
        let apdu = install_for_install_make_selectable(
            &elf,
            &module,
            &instance,
            privileges,
            PrivLen::Canonical,
            &params,
        )
        .unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([
                0x84, 0xE6, 0x0C, 0x00, 0x1A, // Lc = 26
                0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, // Lf | ELF_AID
                0x05, 0xB0, 0x00, 0x00, 0x02, 0x52, // Lm | Module_AID
                0x05, 0xC0, 0x00, 0x00, 0x03, 0x53, // La | Instance_AID
                0x03, 0x80, 0x00, 0x00, // Lp | Privileges (full 3-byte form)
                0x02, 0xC9, 0x00, // Li | 'C9' 00
                0x00, // Lt (token empty)
                0x00, // Le
            ])
        );
    }

    #[test]
    fn install_make_selectable_jcop_emits_one_byte_privileges() {
        // JCOP 4 P71 form: an SD-only privilege collapses to the 1-byte legacy
        // form `01 80` (GPCS v2.3.1 §11.1.2), which is what JCOP 4 P71 expects.
        let elf = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let module = [0xB0, 0x00, 0x00, 0x02, 0x52];
        let instance = [0xC0, 0x00, 0x00, 0x03, 0x53];
        let privileges = [0x80, 0x00, 0x00]; // SD only — fits in byte 1
        let params = [0xC9, 0x00];
        let apdu = install_for_install_make_selectable(
            &elf,
            &module,
            &instance,
            privileges,
            PrivLen::Jcop1Byte,
            &params,
        )
        .unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([
                0x84, 0xE6, 0x0C, 0x00, 0x18, // Lc = 24
                0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, // Lf | ELF_AID
                0x05, 0xB0, 0x00, 0x00, 0x02, 0x52, // Lm | Module_AID
                0x05, 0xC0, 0x00, 0x00, 0x03, 0x53, // La | Instance_AID
                0x01, 0x80, // Lp | Privileges (minimal 1-byte form)
                0x02, 0xC9, 0x00, // Li | 'C9' 00
                0x00, // Lt (token empty)
                0x00, // Le
            ])
        );
    }

    #[test]
    fn install_make_selectable_extended_bit_forces_three_bytes_even_for_jcop() {
        // An extended (2.2+) privilege bit lives in byte 2 or 3, so the full
        // 3-byte field is required and must NOT be truncated (GPCS §11.1.2),
        // regardless of the selected PrivLen.
        let elf = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let module = [0xB0, 0x00, 0x00, 0x02, 0x52];
        let instance = [0xC0, 0x00, 0x00, 0x03, 0x53];
        let privileges = [0x80, 0x00, 0x20]; // SD + an extended-byte-3 bit
        let params = [0xC9, 0x00];
        let apdu = install_for_install_make_selectable(
            &elf,
            &module,
            &instance,
            privileges,
            PrivLen::Jcop1Byte, // even the 1-byte selector must not truncate
            &params,
        )
        .unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([
                0x84, 0xE6, 0x0C, 0x00, 0x1A, // Lc = 26
                0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, // Lf | ELF_AID
                0x05, 0xB0, 0x00, 0x00, 0x02, 0x52, // Lm | Module_AID
                0x05, 0xC0, 0x00, 0x00, 0x03, 0x53, // La | Instance_AID
                0x03, 0x80, 0x00, 0x20, // Lp | Privileges (full 3-byte form)
                0x02, 0xC9, 0x00, // Li | 'C9' 00
                0x00, // Lt
                0x00, // Le
            ])
        );
    }

    #[test]
    fn oversized_params_overflow() {
        let aid = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let params = [0x00u8; 255];
        assert_eq!(
            install_for_install_make_selectable(
                &aid,
                &aid,
                &aid,
                [0; 3],
                PrivLen::Canonical,
                &params
            ),
            Err(BuildError::Overflow)
        );
    }
}
