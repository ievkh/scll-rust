//! Individual CAP components — PDD §5.4a table.
//!
//! `no_std`: this holds parsed *metadata* only — small owned values (AIDs +
//! offsets) — so the collections are bounded `heapless::Vec`, not borrows. The
//! bulk component *bytes* are never held here; they are streamed from the input
//! ZIP by [`super::LoadFileDataBlock`].

use heapless::Vec;

use crate::aid::Aid;
use crate::limits::{MAX_CAP_APPLETS, MAX_CAP_IMPORTS};

/// Extracted CAP components relevant to loading/installing.
pub struct CapComponents {
    pub jc_platform_version: (u8, u8, u8),  // from Header.cap
    pub imports: Vec<Aid, MAX_CAP_IMPORTS>, // Import.cap dependencies
    pub applets: Vec<AppletEntry, MAX_CAP_APPLETS>, // Applet.cap (class AID + install offset)
}

/// One applet class entry from `Applet.cap`.
pub struct AppletEntry {
    pub class_aid: Aid,
    pub install_method_offset: u16,
}
