#!/usr/bin/env bash
# Build and run the scll example binaries against PC/SC or jcsim.
#
# Usage:
#   ./run.sh <demo> [extra args forwarded to the binary]
#
#   <demo> is one of:
#     card-info       probe / discover / card status / inventory (read-only)
#     card-status     life-cycle no-op / refusals (read-only by default;
#                     SCLL_LIFECYCLE_ADVANCE=1 advances OP_READY->INITIALIZED,
#                     jcsim only)
#     key-tools       HOST-ONLY key-backend demo (no card, no transport,
#                     no environment needed)
#     workflow-free   free workflow functions + manager accessors (read-only)
#     ssd-lifecycle   SSD create + personalize + applet + keyset rotation + teardown
#     isd-lifecycle   applet under the ISD + ISD keyset rotation + keyset removal
#     all             run the demos in the order above
#
# Pick a transport by exporting its connection variable (or force with
# SCLL_TRANSPORT=pcsc|jcsim):
#
#   PC/SC:
#     export SCLL_PCSC="uTrust"            # reader-name substring [@index]
#     export SCLL_PCSC_KEY_ENC=...         # ISD keys (hex)
#     export SCLL_PCSC_KEY_MAC=...
#     export SCLL_PCSC_KEY_DEK=...
#
#   jcsim (Oracle simulator via javacard-simulator-apdu-bridge):
#     export SCLL_JCSIM_ADDR=127.0.0.1:10000
#     export SCLL_JCSIM_KEY_ENC=404142434445464748494A4B4C4D4E4F
#     export SCLL_JCSIM_KEY_MAC=404142434445464748494A4B4C4D4E4F
#     export SCLL_JCSIM_KEY_DEK=404142434445464748494A4B4C4D4E4F
#
#   Lifecycle demos only (ssd-lifecycle / isd-lifecycle):
#     export SCLL_CAP=/path/to/scpapplet.cap
#
# isd-lifecycle refuses to run when SCLL_ISD_KVN is 0x30 or 0x31 (it would
# collide with the demo keyset versions — see the binary's docs).
#
# isd-lifecycle opt-ins (both default-off; see the binary's docs):
#   SCLL_ISD_AES256=1        AES-256 demo keysets (SCP03 targets only)
#   SCLL_APPLET_LEVEL=33     requested level for the applet channels
set -euo pipefail
cd "$(dirname "$0")"

usage() {
  echo "usage: $0 {card-info|card-status|key-tools|workflow-free|ssd-lifecycle|isd-lifecycle|all} [args...]" >&2
  exit 2
}

demo="${1:-}"
[[ -n "$demo" ]] || usage
shift

# key-tools is host-only and needs no transport; every other demo does.
if [[ "$demo" != "key-tools" ]] \
  && [[ -z "${SCLL_TRANSPORT:-}" && -z "${SCLL_PCSC:-}" && -z "${SCLL_JCSIM_ADDR:-}" ]]; then
  echo "error: set SCLL_PCSC=<reader> (PC/SC) or SCLL_JCSIM_ADDR=<host:port> (jcsim)" >&2
  exit 2
fi

require_cap() {
  : "${SCLL_CAP:?set SCLL_CAP=/path/to/scpapplet.cap (required by $1)}"
}

run_one() {
  local bin="$1"; shift
  case "$bin" in
    card-info|card-status|key-tools|workflow-free) ;;
    ssd-lifecycle|isd-lifecycle) require_cap "$bin" ;;
    *) usage ;;
  esac
  # cargo run compiles (release) and then runs the selected binary.
  cargo run --release --bin "$bin" -- "$@"
}

case "$demo" in
  all)
    run_one key-tools "$@"
    run_one card-info "$@"
    run_one card-status "$@"
    run_one workflow-free "$@"
    run_one ssd-lifecycle "$@"
    run_one isd-lifecycle "$@"
    ;;
  *)
    run_one "$demo" "$@"
    ;;
esac
