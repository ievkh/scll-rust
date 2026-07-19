# SCP02 / SCP03 flow KAT vectors

Two **independent** references (one per protocol), implemented on
`pyca/cryptography`, are the out-of-process oracles described in PDD §10.2. Each derives the session keys, cryptograms, command/response
wrapping and the PUT KEY block; the values they print are the ones asserted by
the corresponding Rust KAT test. They are committed for **reproducibility
only** — CI is Rust-only and never runs them.

```
python3 scp03_ref.py    # -> values asserted by tests/scp03_kat.rs
python3 scp02_ref.py    # -> values asserted by tests/scp02_kat.rs
```

## `scp03_ref.py` (Amendment D v1.1.2 S8 + v1.2 S16)

Emits flow vectors for **both** size modes — S8 (8-byte challenges/cryptograms,
8-byte truncated MACs, `L=0x0040`) and S16 (16-byte challenges/cryptograms, full
16-byte MACs, `L=0x0080`) — plus the pseudo-random card-challenge derivation
(§6.2.2.1: KDF keyed by Key-ENC, constant `0x02`, context `seq ‖ invoker_AID`).
The S8 output reproduces the originally committed vectors byte-for-byte, which is
the regression anchor; the S16 and pseudo-challenge values feed the matching
`scp03_kat.rs` tests.

Provenance of the inputs:

* Static keys `40..4F` — the GlobalPlatform well-known default ("test") keyset
  (e.g. YubiKey SCP03 default keyset; GlobalPlatformPro `--key 40..4F`).
* Primitives cross-checked against published vectors: AES-128 (FIPS-197 §C.1),
  AES-CMAC (RFC 4493 / NIST SP 800-38B). The KDF layout/constants follow
  Amendment D §4.1.5 / Table 4-1.

## `scp02_ref.py` (GPCS v2.3.1 Appendix E, i=0x55)

A line-for-line mirror of GlobalPlatformPro's `SCP02Wrapper` / `GPCrypto`
(validated against real JCOP cards) over the same default keyset `40..4F`:

* **3DES** is two-key EDE2 (16-byte key); single-DES is anchored to the FIPS-81
  KAT (`key 0123456789ABCDEF`, PT `4E6F772069732074` → `3FA40E8A984D4815`),
  reproduced in `src/crypto.rs`.
* Session keys: `3DES-CBC(constant ‖ seq ‖ 0…, base, zero IV)` (§E.4.1).
* Cryptograms: full 3DES-CBC MAC under S-ENC (§E.5.1).
* C-MAC: ISO/IEC 9797-1:2011 Algorithm 3 "Retail MAC"; per-command ICV is the
  single-DES-ECB encryption of the previous C-MAC (i=0x55; §E.4.4).
* C-DECRYPTION: 3DES-CBC under S-ENC, zero IV; PUT KEY: 3DES-ECB under the DEK
  (§E.5.2).

**R-MAC divergence (documented).** The `Scp02Rmac` block follows the GPCS
§E.4.4 padding rule literally: the R-MAC input is `0x80`-padded **once** before
the Retail MAC. GlobalPlatformPro's `unwrap` applies an explicit `pad80` and
then calls `mac_des_3des`, which pads **again** (a double pad). This library and
this reference both follow the spec (single pad). The default SCP02 level
`0x03` carries no R-MAC, so this affects only level `0x11`/`0x13`. The
C-MAC / C-DECRYPTION / cryptogram / derivation paths match GlobalPlatformPro
byte-for-byte.

`gppro` is used here only as a wire-behaviour oracle, not as a normative
authority; all cryptographic claims are anchored to the published standards
above.
