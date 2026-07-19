//! Fuzz target #2 (PDD §10.5) — card-response parsers. Each consumes bytes a
//! malicious or buggy card controls; the property is total parsing (no panic,
//! malformed input → typed `TlvError`). Drives the raw TLV layer plus all
//! §5.2 / §5.12 / §5.12a templates: CRD '66', key-info '00E0', CCI '67',
//! GET STATUS 'E3' (single-ISD and full multi-scope registry).
#![no_main]
use libfuzzer_sys::fuzz_target;

use scll_core::response;

fuzz_target!(|data: &[u8]| {
    let _ = scll_core::tlv::parse(data);
    let _ = response::parse_card_recognition(data);
    let _ = response::parse_key_information(data);
    let _ = response::parse_card_capabilities(data);
    let _ = response::parse_status_e3(data);
    let _ = response::parse_status_registry(data);
});
