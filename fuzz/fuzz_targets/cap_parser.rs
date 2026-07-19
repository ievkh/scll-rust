//! Fuzz target #1 (PDD §10.5) — top priority: the CAP parser consumes an
//! attacker-influenceable ZIP. Asserts: no panic, no UB, malformed input yields
//! a typed [`scll_core::cap::CapError`]. On a successful parse the streaming
//! Load File Data Block is also drained, so the ZIP walk, the STORED copy path
//! and the DEFLATE wrapping-ring inflate are all exercised.
#![no_main]
use libfuzzer_sys::fuzz_target;

use scll_core::cap::{parse, InflateCtx};

fuzz_target!(|data: &[u8]| {
    let mut infl = InflateCtx::new();
    if let Ok(cap) = parse(data, &mut infl) {
        let mut lfdb = cap.lfdb();
        let mut buf = [0u8; 240];
        // Bound pathological / zip-bomb-shaped inputs so the iteration stays
        // cheap; correctness (never-panic) is the property under test.
        let mut guard: u32 = 0;
        loop {
            match lfdb.next_block(&mut infl, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            guard += 1;
            if guard > 100_000 {
                break;
            }
        }
    }
});
