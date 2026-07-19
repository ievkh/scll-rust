#!/usr/bin/env bash
#
# Local mirror of the CI gates in .github/workflows/ci.yml — run this before
# pushing to confirm the workspace isn't broken, in one command:
#
#     ./check.sh                 # fast gates: fmt, clippy, test, backend KATs, jcsim
#     FULL=1 ./check.sh          # also: cargo-deny + the fuzz-smoke seed replay
#     SCLL_JCSIM_ADDR=127.0.0.1:10000 ./check.sh   # also run the live jcsim transport test
#     SCLL_PCSC='<reader>[@<index>]' ./check.sh     # also run the PC/SC reader-only smoke
#     # each secure-channel smoke needs all three per-role keys (32/48/64 hex each, same length):
#     SCLL_JCSIM_ADDR=127.0.0.1:10000 SCLL_JCSIM_KEY_ENC=.. SCLL_JCSIM_KEY_MAC=.. SCLL_JCSIM_KEY_DEK=.. ./check.sh
#     SCLL_PCSC='<reader>' SCLL_PCSC_KEY_ENC=.. SCLL_PCSC_KEY_MAC=.. SCLL_PCSC_KEY_DEK=.. ./check.sh
#
# Mirrors the CI jobs: fmt, clippy, test (+ the backend `std` KAT run), deny,
# fuzz-smoke, the two jcsim integration tests, and the PC/SC real-card smoke
# (jcsim tests auto-skip unless SCLL_JCSIM_ADDR points at a running
# javacard-simulator-apdu-bridge; the jcsim secure-channel smoke also needs the
# three SCLL_JCSIM_KEY_ENC/_MAC/_DEK. PC/SC tests auto-skip unless SCLL_PCSC
# names a present reader; its secure-channel test also needs the three
# SCLL_PCSC_KEY_ENC/_MAC/_DEK).
#
# Prerequisites (same as CI):
#   * a >= 1.81 stable toolchain with rustfmt + clippy (workspace MSRV is 1.81)
#   * libpcsclite-dev — the PC/SC transport crate links it
#       Debian/Ubuntu:  sudo apt-get install -y libpcsclite-dev
#       Fedora:         sudo dnf install pcsc-lite-devel
#       macOS:          (PCSC framework ships with the OS)
#   * FULL=1 also needs: cargo-deny, and nightly + cargo-fuzz
set -euo pipefail

# CI denies all warnings (rustc + clippy pedantic) — match that here.
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
export CARGO_TERM_COLOR=always

bold=$'\033[1m'; blue=$'\033[1;34m'; green=$'\033[1;32m'; yellow=$'\033[1;33m'; reset=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$blue" "$*" "$reset"; }
note() { printf '%s    %s%s\n' "$yellow" "$*" "$reset"; }

start=$(date +%s)

# 1. Formatting (CI job: fmt)
step "fmt — cargo fmt --all --check"
cargo fmt --all --check

# 2. Lints, all targets, pedantic-as-error via RUSTFLAGS (CI job: clippy)
step "clippy — cargo clippy --workspace --all-targets"
cargo clippy --workspace --all-targets

# 3. Workspace tests incl. all crates' doctests (CI job: test, step 1)
step "test — cargo test --workspace"
cargo test --workspace

# 4. Backend KAT suite with the host critical-section impl (CI job: test, step 2)
step "test — cargo test -p scll-backend-rustcrypto --features std  (SCP02/SCP03 KATs)"
cargo test -p scll-backend-rustcrypto --features std

# 5. jcsim integration tests (CI job: smoke-jcsim, + transport connect test).
#    Auto-skips both unless SCLL_JCSIM_ADDR is set; compiles them regardless so
#    they cannot bit-rot.
step "jcsim — compile guard + connect_selects_isd + smoke_jcsim (gated on SCLL_JCSIM_ADDR; key step on SCLL_JCSIM_KEY_ENC/_MAC/_DEK)"
cargo test -p scll --features "jcsim std" --test smoke_jcsim --no-run   # compile guard
cargo test-jcsim -- --nocapture
if [[ -z "${SCLL_JCSIM_ADDR:-}" ]]; then
  note "SCLL_JCSIM_ADDR not set — jcsim tests were skipped (set it to a running bridge to run them)."
elif [[ -z "${SCLL_JCSIM_KEY_ENC:-}" || -z "${SCLL_JCSIM_KEY_MAC:-}" || -z "${SCLL_JCSIM_KEY_DEK:-}" ]]; then
  note "SCLL_JCSIM_KEY_ENC/_MAC/_DEK not all set — the jcsim secure-channel smoke was skipped (connect_selects_isd ran)."
fi

# 5b. PC/SC real-card smoke (CI job: smoke-pcsc). Mirrors the jcsim block but
#     drives a physical reader/card through scll-transport-pcsc. Auto-skips
#     unless a reader is named in SCLL_PCSC; the secure-channel test additionally
#     needs all three SCLL_PCSC_KEY_ENC/_MAC/_DEK (a wrong key burns an SD retry,
#     GPCS §11, so it is never run without operator-supplied keys). Compiled
#     regardless so it cannot bit-rot.
step "pcsc — compile guard + smoke_pcsc (gated on SCLL_PCSC; key step on SCLL_PCSC_KEY_ENC/_MAC/_DEK)"
cargo test -p scll --features "pcsc std" --test smoke_pcsc --no-run   # compile guard
cargo test-pcsc -- --nocapture
if [[ -z "${SCLL_PCSC:-}" ]]; then
  note "SCLL_PCSC not set — PC/SC smoke tests were skipped (set SCLL_PCSC=<reader-name-substring>[@<index>] with a card present to run them)."
elif [[ -z "${SCLL_PCSC_KEY_ENC:-}" || -z "${SCLL_PCSC_KEY_MAC:-}" || -z "${SCLL_PCSC_KEY_DEK:-}" ]]; then
  note "SCLL_PCSC_KEY_ENC/_MAC/_DEK not all set — the key-requiring PC/SC test was skipped (the reader-only test ran)."
fi

# 6. Optional heavier gates (FULL=1): supply-chain policy + short fuzz replay.
if [[ "${FULL:-0}" == "1" ]]; then
  step "deny — cargo deny check  (license/advisory policy)"
  if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
  else
    note "cargo-deny not installed (cargo install cargo-deny --locked) — skipping."
  fi

  step "fuzz-smoke — replay checked-in seed corpora (30s/target, no new inputs)"
  # card_response_parsers covers both GET STATUS decoders: parse_status_e3 (§5.12)
  # and parse_status_registry (§5.12a, full multi-scope inventory).
  if command -v cargo-fuzz >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -q nightly; then
    for t in cap_parser card_response_parsers rapdu_unwrap; do
      cargo +nightly fuzz run "$t" fuzz/seeds/"$t" -- -max_total_time=30 -runs=0
    done
  else
    note "cargo-fuzz and/or a nightly toolchain missing — skipping fuzz-smoke."
    note "  rustup toolchain install nightly && cargo install cargo-fuzz --locked"
  fi
fi

end=$(date +%s)
printf '\n%sALL CHECKS PASSED%s  (%ss)\n' "$green" "$reset" "$((end - start))"
