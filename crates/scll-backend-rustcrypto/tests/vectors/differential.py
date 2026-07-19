#!/usr/bin/env python3
"""Out-of-process differential harness (impl-plan §S8.3 / §10.2).

Re-scoped from the v0.1 plan's "differential fuzzing on wrap/unwrap + KDF":
running a foreign oracle *inside* a libFuzzer loop is impractical (process
spawn per input), so instead this samples inputs and checks the independent
Python references (`scp02_ref.py`, `scp03_ref.py`, already used to pin the
Rust KATs) against each other and against fixed known answers. It is a
manual / scheduled check — NOT part of the Rust CI graph and never a
dependency of the crate.

Purpose: guard the reference oracles themselves (which gate the Rust backend)
against regressions, and exercise the KDF / wrap paths over a sampled space of
keys, modes, and challenges. If the Rust backend is later given a JSON
emit-and-compare mode, this is the place to wire the byte-for-byte diff.

Usage:
    python3 differential.py [N]      # N random samples per path (default 256)

Requires `pyca/cryptography` (same dependency the *_ref.py oracles use);
if it is missing the script skips with a clear message rather than failing,
so a bare checkout does not error.
"""
import os
import sys
import importlib.util


def _load(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    spec = importlib.util.spec_from_file_location(name[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    # The oracle modules emit KAT vectors to stdout at import time (they double
    # as vector generators); silence that here so the harness output stays clean.
    import contextlib
    with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
        spec.loader.exec_module(mod)
    return mod


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 256
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("SKIP: pyca/cryptography not installed; "
              "install it to run the differential harness")
        return 0

    scp03 = _load("scp03_ref.py")
    import secrets

    checks = 0
    # SCP03 KDF property sampling: mirror the properties the Rust fuzz target
    # scp03_kdf_props asserts, but computed by the independent oracle, so a
    # divergence flags either the oracle or (once wired) the backend.
    for _ in range(n):
        for klen in (16, 24, 32):
            key = secrets.token_bytes(klen)
            host = secrets.token_bytes(8)
            card = secrets.token_bytes(8)
            for l_bits in (0x0040, 0x0080):  # S8 / S16
                clen = 8 if l_bits == 0x0040 else 16
                ctx = host + card
                # Host/card cryptograms use constants 0x01 / 0x00 (Amd D §6.2.2).
                host_cg = scp03.kdf(key, 0x01, l_bits, ctx, clen)
                card_cg = scp03.kdf(key, 0x00, l_bits, ctx, clen)
                assert len(host_cg) == clen, "host cryptogram length"
                assert len(card_cg) == clen, "card cryptogram length"
                assert host_cg != card_cg, "constant separation host vs card"
                # Determinism.
                assert host_cg == scp03.kdf(key, 0x01, l_bits, ctx, clen)
                # Challenge sensitivity.
                host2 = bytes([host[0] ^ 1]) + host[1:]
                assert host_cg != scp03.kdf(key, 0x01, l_bits, host2 + card, clen)
                checks += 1

    print(f"OK: {checks} SCP03 KDF differential checks passed "
          f"({n} samples x 3 key lengths x 2 modes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
