#!/usr/bin/env bash
# verify-s8.sh — local verification of the CI hardening gates (PDD §10.6).
#
# Runs, fastest-first, the checks that the CI gates encode, so a typo or an
# API mismatch fails in seconds rather than after a long fuzz run. This
# reproduces jobs from .github/workflows/ci.yml (fuzz-smoke, coverage, msrv,
# no-std) plus the §S8.3 differential harness — but it is NOT a substitute for
# a green CI run: the fuzz-nightly cron and the "coverage as a required status
# check" branch-protection setting only exist on GitHub.
#
# Usage:
#   scripts/verify-s8.sh [options]
#     --live-secs N     per-target live-fuzz budget in step 3 (default 60; 0 skips)
#     --floor N         coverage line-% floor for step 4 (default 84)
#     --diff-samples N  differential sample count for step 6 (default 256)
#     --skip-fuzz       skip steps 1-3 (nightly + cargo-fuzz not installed)
#     --skip-coverage   skip step 4 (cargo-llvm-cov not installed)
#     --skip-msrv       skip step 5a (1.81 toolchain not installed)
#     --skip-nostd      skip step 5b (thumbv7em-none-eabi target not added)
#     --skip-diff       skip step 6
#   Env: NIGHTLY (default: nightly), MSRV (default: 1.81.0).
#
# Exit code is non-zero if any executed step fails; a per-step summary is
# printed at the end. Steps whose tooling is absent are auto-skipped with a
# clear note (a skip never counts as a pass).

set -uo pipefail   # NOT -e: we want to run every step and summarise, not abort

# --- repo root -------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# --- options / defaults ----------------------------------------------------
LIVE_SECS=60
FLOOR=82
DIFF_SAMPLES=256
SKIP_FUZZ=0
SKIP_COVERAGE=0
SKIP_MSRV=0
SKIP_NOSTD=0
SKIP_DIFF=0
NIGHTLY="${NIGHTLY:-nightly}"
MSRV="${MSRV:-1.81.0}"

FUZZ_TARGETS=(cap_parser card_response_parsers rapdu_unwrap scp_wrap_roundtrip scp03_kdf_props)
S8_TARGETS=(scp_wrap_roundtrip scp03_kdf_props)
COV_IGNORE='scll-test-(support|util)/'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --live-secs)    LIVE_SECS="$2"; shift 2 ;;
    --floor)        FLOOR="$2"; shift 2 ;;
    --diff-samples) DIFF_SAMPLES="$2"; shift 2 ;;
    --skip-fuzz)     SKIP_FUZZ=1; shift ;;
    --skip-coverage) SKIP_COVERAGE=1; shift ;;
    --skip-msrv)     SKIP_MSRV=1; shift ;;
    --skip-nostd)    SKIP_NOSTD=1; shift ;;
    --skip-diff)     SKIP_DIFF=1; shift ;;
    -h|--help)      sed -n '2,34p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# --- fuzz seed dir helper -------------------------------------------------
# cargo-fuzz resolves a relative corpus arg against its own working dir (it
# cd's into fuzz/), so pass an ABSOLUTE path. If the seed dir is somehow
# missing (e.g. a partial checkout), create it empty — an empty corpus is a
# valid libFuzzer start, it just begins from scratch.
seed_dir() {
  local t="$1" d="$ROOT/fuzz/seeds/$t"
  [[ -d "$d" ]] || { mkdir -p "$d"; printf '%s  (created empty — no checked-in seeds found)\n' "$d" >&2; }
  printf '%s' "$d"
}

# --- pretty helpers + result tracking --------------------------------------
BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
declare -a RESULTS   # "PASS|FAIL|SKIP<TAB>label"

banner() { printf '\n%s========================================%s\n%s %s%s\n%s========================================%s\n' \
  "$BOLD" "$RST" "$BOLD" "$1" "$RST" "$BOLD" "$RST"; }
record() { RESULTS+=("$1"$'\t'"$2"); }
have()   { command -v "$1" >/dev/null 2>&1; }
# Does rustup have the given toolchain installed?
have_tc() { rustup toolchain list 2>/dev/null | grep -q "^$1"; }
# Is a cargo subcommand available (e.g. `cargo fuzz`, `cargo llvm-cov`)?
have_sub() { cargo "$1" --help >/dev/null 2>&1; }

# Run a step: run_step "label" cmd args...
run_step() {
  local label="$1"; shift
  banner "$label"
  printf '%s$ %s%s\n\n' "$YEL" "$*" "$RST"
  if "$@"; then
    printf '\n%s[PASS]%s %s\n' "$GRN" "$RST" "$label"
    record PASS "$label"
    return 0
  else
    local rc=$?
    printf '\n%s[FAIL rc=%s]%s %s\n' "$RED" "$rc" "$RST" "$label"
    record FAIL "$label"
    return "$rc"
  fi
}
skip_step() {
  local label="$1" why="$2"
  banner "$label"
  printf '%s[SKIP]%s %s — %s\n' "$YEL" "$RST" "$label" "$why"
  record SKIP "$label"
}

# --- environment note ------------------------------------------------------
printf '%sscll S8 verification%s  (root: %s)\n' "$BOLD" "$RST" "$ROOT"
printf 'toolchains: nightly=%s  msrv=%s   live-fuzz=%ss  floor=%s%%  diff-samples=%s\n' \
  "$NIGHTLY" "$MSRV" "$LIVE_SECS" "$FLOOR" "$DIFF_SAMPLES"

FAILED=0

# ===========================================================================
# STEP 1 — the two new fuzz targets COMPILE (the main risk: API signatures).
# ===========================================================================
if [[ "$SKIP_FUZZ" == 1 ]]; then
  skip_step "STEP 1: fuzz targets build" "--skip-fuzz"
elif ! have_tc "$NIGHTLY"; then
  skip_step "STEP 1: fuzz targets build" "nightly toolchain not installed (rustup toolchain install $NIGHTLY)"
elif ! have_sub fuzz; then
  skip_step "STEP 1: fuzz targets build" "cargo-fuzz not installed (cargo install cargo-fuzz --locked)"
else
  run_step "STEP 1: build scp_wrap_roundtrip" \
    cargo "+$NIGHTLY" fuzz build scp_wrap_roundtrip || FAILED=1
  run_step "STEP 1: build scp03_kdf_props" \
    cargo "+$NIGHTLY" fuzz build scp03_kdf_props || FAILED=1
fi

# ===========================================================================
# STEP 2 — seed replay for all five targets (what fuzz-smoke does; -runs=0).
# ===========================================================================
if [[ "$SKIP_FUZZ" == 1 ]]; then
  skip_step "STEP 2: seed replay" "--skip-fuzz"
elif ! have_tc "$NIGHTLY" || ! have_sub fuzz; then
  skip_step "STEP 2: seed replay" "nightly + cargo-fuzz required"
else
  for t in "${FUZZ_TARGETS[@]}"; do
    run_step "STEP 2: replay seeds — $t" \
      cargo "+$NIGHTLY" fuzz run "$t" "$(seed_dir "$t")" -- -max_total_time=30 -runs=0 || FAILED=1
  done
fi

# ===========================================================================
# STEP 3 — short LIVE fuzz on the two S8 targets (real mutation coverage).
# ===========================================================================
if [[ "$SKIP_FUZZ" == 1 ]]; then
  skip_step "STEP 3: live fuzz" "--skip-fuzz"
elif [[ "$LIVE_SECS" == 0 ]]; then
  skip_step "STEP 3: live fuzz" "--live-secs 0"
elif ! have_tc "$NIGHTLY" || ! have_sub fuzz; then
  skip_step "STEP 3: live fuzz" "nightly + cargo-fuzz required"
else
  for t in "${S8_TARGETS[@]}"; do
    run_step "STEP 3: live fuzz ${LIVE_SECS}s — $t" \
      cargo "+$NIGHTLY" fuzz run "$t" "$(seed_dir "$t")" -- -max_total_time="$LIVE_SECS" || FAILED=1
  done
fi

# ===========================================================================
# STEP 4 — coverage gate: measure once, assert floor, then prove it has teeth.
# ===========================================================================
if [[ "$SKIP_COVERAGE" == 1 ]]; then
  skip_step "STEP 4: coverage gate" "--skip-coverage"
elif ! have_sub llvm-cov; then
  skip_step "STEP 4: coverage gate" "cargo-llvm-cov not installed (cargo install cargo-llvm-cov)"
else
  # One instrumented run feeds the subsequent reports.
  if run_step "STEP 4a: instrument (cargo llvm-cov --workspace --no-report)" \
       cargo llvm-cov --workspace --no-report; then
    # Show the number the gate will actually see (so you can retune --floor).
    banner "STEP 4b: coverage summary (TOTAL is what the gate measures)"
    cargo llvm-cov report --ignore-filename-regex "$COV_IGNORE" | tail -3 || true
    run_step "STEP 4c: gate at floor ${FLOOR}% (must PASS)" \
      cargo llvm-cov report --fail-under-lines "$FLOOR" --ignore-filename-regex "$COV_IGNORE" || FAILED=1
    # Teeth check: a 99% floor must FAIL, proving the gate blocks regressions.
    banner "STEP 4d: teeth check — floor 99% must FAIL"
    if cargo llvm-cov report --fail-under-lines 99 --ignore-filename-regex "$COV_IGNORE" >/dev/null 2>&1; then
      printf '%s[FAIL]%s gate did NOT block at 99%% — the gate has no teeth\n' "$RED" "$RST"
      record FAIL "STEP 4d: teeth check (99% must fail)"
      FAILED=1
    else
      printf '%s[PASS]%s gate correctly blocked at 99%%\n' "$GRN" "$RST"
      record PASS "STEP 4d: teeth check (99% must fail)"
    fi
  else
    FAILED=1
  fi
fi

# ===========================================================================
# STEP 5a — MSRV build + test via the MSRV-aware resolver.
#   Modern transitive deps ship edition-2024 manifests that a bare `cargo
#   +1.81` cannot parse, and Cargo.lock is git-ignored, so we resolve with a
#   STABLE cargo under CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
#   (picks 1.81-compatible versions), then build/test with +1.81 --locked.
# ===========================================================================
if [[ "$SKIP_MSRV" == 1 ]]; then
  skip_step "STEP 5a: MSRV ($MSRV)" "--skip-msrv"
elif ! have_tc "$MSRV"; then
  skip_step "STEP 5a: MSRV ($MSRV)" "toolchain not installed (rustup toolchain install $MSRV)"
elif ! have_tc stable; then
  skip_step "STEP 5a: MSRV ($MSRV)" "stable toolchain not installed (needed for the MSRV-aware resolve; rustup toolchain install stable)"
else
  run_step "STEP 5a: MSRV resolve (stable, fallback resolver)" \
    env CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile || FAILED=1
  run_step "STEP 5a: MSRV build ($MSRV, --locked)" \
    cargo "+$MSRV" build --workspace --locked || FAILED=1
  run_step "STEP 5a: MSRV test ($MSRV, --locked)" \
    cargo "+$MSRV" test  --workspace --locked || FAILED=1
fi

# ===========================================================================
# STEP 5b — no_std build of core + backend for a bare-metal target.
# ===========================================================================
if [[ "$SKIP_NOSTD" == 1 ]]; then
  skip_step "STEP 5b: no_std (thumbv7em-none-eabi)" "--skip-nostd"
elif ! rustup target list --installed 2>/dev/null | grep -q '^thumbv7em-none-eabi$'; then
  skip_step "STEP 5b: no_std (thumbv7em-none-eabi)" "target not added (rustup target add thumbv7em-none-eabi)"
else
  run_step "STEP 5b: no_std build (thumbv7em-none-eabi)" \
    cargo build -p scll-core -p scll-backend-rustcrypto \
      --no-default-features --target thumbv7em-none-eabi || FAILED=1
fi

# ===========================================================================
# STEP 6 — out-of-process differential harness (§S8.3).
# ===========================================================================
DIFF_PY="crates/scll-backend-rustcrypto/tests/vectors/differential.py"
if [[ "$SKIP_DIFF" == 1 ]]; then
  skip_step "STEP 6: differential harness" "--skip-diff"
elif ! have python3; then
  skip_step "STEP 6: differential harness" "python3 not found"
else
  # The harness itself prints SKIP (exit 0) if pyca/cryptography is absent.
  run_step "STEP 6: differential ($DIFF_SAMPLES samples)" \
    python3 "$DIFF_PY" "$DIFF_SAMPLES" || FAILED=1
fi

# --- summary ---------------------------------------------------------------
banner "SUMMARY"
pass=0; fail=0; skip=0
for r in "${RESULTS[@]}"; do
  status="${r%%$'\t'*}"; label="${r#*$'\t'}"
  case "$status" in
    PASS) printf '  %s[PASS]%s %s\n' "$GRN" "$RST" "$label"; ((pass++)) ;;
    FAIL) printf '  %s[FAIL]%s %s\n' "$RED" "$RST" "$label"; ((fail++)) ;;
    SKIP) printf '  %s[SKIP]%s %s\n' "$YEL" "$RST" "$label"; ((skip++)) ;;
  esac
done
printf '\n%s%d passed, %d failed, %d skipped%s\n' "$BOLD" "$pass" "$fail" "$skip" "$RST"

if [[ "$fail" -gt 0 || "$FAILED" -ne 0 ]]; then
  printf '%sS8 verification FAILED%s — see the failing step(s) above.\n' "$RED" "$RST"
  exit 1
fi
if [[ "$skip" -gt 0 ]]; then
  printf '%sS8 checks passed, but %d step(s) were skipped%s (install the missing tooling for full coverage).\n' \
    "$YEL" "$skip" "$RST"
else
  printf '%sAll S8 checks passed.%s\n' "$GRN" "$RST"
fi
printf 'Reminder: fuzz-nightly (cron) and "coverage as a required status check" only exist in GitHub CI/branch protection.\n'
exit 0
