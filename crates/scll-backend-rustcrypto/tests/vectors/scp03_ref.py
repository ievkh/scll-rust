#!/usr/bin/env python3
"""Independent SCP03 reference (Amendment D v1.1.2 + v1.2 S16) using
pyca/cryptography. Out-of-process oracle per impl-plan §10.2. Emits flow KAT
vectors that the Rust backend must reproduce byte-for-byte. Not part of CI
(Rust-only).

Mode handling (Amendment D §5.1 Table 5-1, bit b4 0x08):
  * S8  — 8-byte challenges/cryptograms, 8-byte (truncated) MACs, L = 0x0040.
  * S16 — 16-byte challenges/cryptograms, full 16-byte MACs, L = 0x0080.
The MAC chaining value is 16 bytes in both modes.
"""
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
B = default_backend()

def aes_cmac(key, data):
    c = CMAC(algorithms.AES(key), backend=B); c.update(data); return c.finalize()

def aes_ecb_block(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB(), backend=B).encryptor()
    return e.update(block) + e.finalize()

def aes_cbc(key, iv, data):
    e = Cipher(algorithms.AES(key), modes.CBC(iv), backend=B).encryptor()
    return e.update(data) + e.finalize()

def aes_cbc_dec(key, iv, data):
    d = Cipher(algorithms.AES(key), modes.CBC(iv), backend=B).decryptor()
    return d.update(data) + d.finalize()

def kdf(key, const, l_bits, context, out_len):
    """SCP03 data-derivation (Amd D §4.1.5): SP800-108 counter mode, CMAC PRF.
    block = label(11*00||const) || 0x00 || L(2,BE) || i(1) || context."""
    label = b"\x00"*11 + bytes([const])
    out = b""; i = 1
    while len(out) < out_len:
        block = label + b"\x00" + l_bits.to_bytes(2, "big") + bytes([i]) + context
        out += aes_cmac(key, block); i += 1
    return out[:out_len]

def pad80(data, block=16):
    data = data + b"\x80"
    while len(data) % block: data += b"\x00"
    return data

def unpad80(data):
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00: i -= 1
    assert i >= 0 and data[i] == 0x80, "bad pad"
    return data[:i]

SL_CMAC, SL_CENC, SL_RMAC, SL_RENC = 0x01, 0x02, 0x10, 0x20

class Scp03:
    def __init__(self, kenc, kmac, host, card, level):
        assert len(host) == len(card), "challenge lengths must match"
        self.kenc, self.kmac = kenc, kmac
        self.field = len(host)            # 8 (S8) or 16 (S16)
        self.l_field = self.field * 8     # 0x0040 (S8) or 0x0080 (S16)
        kbits = len(kenc)*8
        ctx = host + card
        self.senc  = kdf(kenc, 0x04, kbits, ctx, len(kenc))
        self.smac  = kdf(kmac, 0x06, kbits, ctx, len(kmac))
        self.srmac = kdf(kmac, 0x07, kbits, ctx, len(kmac))
        self.host, self.card = host, card
        self.card_crypto = kdf(self.smac, 0x00, self.l_field, ctx, self.field)
        self.host_crypto = kdf(self.smac, 0x01, self.l_field, ctx, self.field)
        self.level = level
        self.chain = b"\x00"*16
        self.ctr = 0
        self.authed = False

    def icv(self, response):
        blk = self.ctr.to_bytes(16, "big")
        if response: blk = bytes([0x80]) + blk[1:]
        return aes_ecb_block(self.senc, blk)

    def wrap(self, capdu):
        cla, ins, p1, p2 = capdu[0], capdu[1], capdu[2], capdu[3]
        # GlobalPlatform secure-messaging bit (b3): MAC over and transmit with
        # CLA | 0x04 (0x80 -> 0x84). Amendment D Figure in section 6.2.4.
        new_cla = cla | 0x04
        lc = capdu[4] if len(capdu) > 4 else 0
        data = capdu[5:5+lc] if len(capdu) > 4 else b""
        le = capdu[5+lc:] if len(capdu) > 4 else b""   # trailing Le (Case 4)
        if not self.authed:                       # EXTERNAL AUTHENTICATE
            assert ins == 0x82
            self.level = p1                        # F1: latch level from EA P1
            body = data
            mac_lc = len(body) + self.field
            mac_in = self.chain + bytes([new_cla, ins, p1, p2, mac_lc]) + body
            full = aes_cmac(self.smac, mac_in)
            self.chain = full
            self.authed = True
            return bytes([new_cla, ins, p1, p2, mac_lc]) + body + full[:self.field] + le
        self.ctr += 1
        body = data
        if self.level & SL_CENC and body:
            body = aes_cbc(self.senc, self.icv(False), pad80(body))
        mac_lc = len(body) + self.field
        mac_in = self.chain + bytes([new_cla, ins, p1, p2, mac_lc]) + body
        full = aes_cmac(self.smac, mac_in)
        self.chain = full
        return bytes([new_cla, ins, p1, p2, mac_lc]) + body + full[:self.field] + le

    def make_response(self, plaintext, sw):
        """Build a card response (encrypt+RMAC) the way a card would, for unwrap KATs."""
        data = plaintext
        if self.level & SL_RENC and data:
            data = aes_cbc(self.senc, self.icv(True), pad80(data))
        out = data
        if self.level & SL_RMAC:
            mac_in = self.chain + data + sw
            out = data + aes_cmac(self.srmac, mac_in)[:self.field]
        return out + sw

    def unwrap(self, rapdu):
        sw = rapdu[-2:]
        body = rapdu[:-2]
        if self.level & SL_RMAC:
            rmac = body[-self.field:]; data = body[:-self.field]
            mac_in = self.chain + data + sw
            assert aes_cmac(self.srmac, mac_in)[:self.field] == rmac, "R-MAC fail"
        else:
            data = body
        if self.level & SL_RENC and data:
            data = unpad80(aes_cbc_dec(self.senc, self.icv(True), data))
        return data + sw

def pseudo_card_challenge(kenc, field, seq, aid):
    """Pseudo-random card challenge (Amd D §6.2.2.1): KDF keyed by Key-ENC,
    constant 0x02, context = sequence_counter(3) || invoker_AID."""
    l_field = field * 8
    return kdf(kenc, 0x02, l_field, seq + aid, field)

def hx(b): return b.hex().upper()

# GlobalPlatform well-known default static keys (dev cards): 40..4F.
KENC = bytes(range(0x40, 0x50)); KMAC = bytes(range(0x40, 0x50)); KDEK = bytes(range(0x40, 0x50))
HOST = bytes.fromhex("0001020304050607")
CARD = bytes.fromhex("08090A0B0C0D0E0F")
HOST16 = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
CARD16 = bytes.fromhex("101112131415161718191A1B1C1D1E1F")

def emit(tag, host, card):
    print(f"\n# ==== SCP03 {tag} flow vectors (default keys 40..4F) ====")
    print("HOST_CHALLENGE =", hx(host)); print("CARD_CHALLENGE =", hx(card))
    field = len(host)
    for level in (0x33, 0x13, 0x03):
        s = Scp03(KENC, KMAC, host, card, level)
        print(f"\n## {tag} level 0x{level:02X}")
        print("S_ENC  =", hx(s.senc)); print("S_MAC  =", hx(s.smac)); print("S_RMAC =", hx(s.srmac))
        print("CARD_CRYPTOGRAM =", hx(s.card_crypto)); print("HOST_CRYPTOGRAM =", hx(s.host_crypto))
        ea_plain = bytes([0x84,0x82,level,0x00,field]) + s.host_crypto
        ea = s.wrap(ea_plain)
        print("EA_WRAPPED =", hx(ea))
        print("CHAIN_AFTER_EA =", hx(s.chain))
        cmd_plain = bytes([0x80,0xE6,0x00,0x00,0x05]) + bytes.fromhex("0102030405")
        wrapped = s.wrap(cmd_plain)
        print("CMD_PLAINTEXT =", hx(cmd_plain))
        print("CMD_WRAPPED   =", hx(wrapped))
        print("CTR_AFTER_CMD =", s.ctr)
        resp_plain = bytes.fromhex("00A40400")
        sw = bytes.fromhex("9000")
        wire = s.make_response(resp_plain, sw)
        print("RESP_PLAINTEXT =", hx(resp_plain + sw))
        print("RESP_WIRE      =", hx(wire))
        got = s.unwrap(wire)
        assert got == resp_plain + sw, (hx(got), hx(resp_plain+sw))
        print("UNWRAP_OK = True")

print("KENC = KMAC = KDEK =", hx(KENC))
emit("S8", HOST, CARD)
emit("S16", HOST16, CARD16)

# Pseudo-random card challenge (Amd D §6.2.2.1) for the new backend method KAT.
# invoker AID = an example SD AID; sequence counter = 00 00 01.
AID = bytes.fromhex("A000000151000000")
SEQ = bytes.fromhex("000001")
print("\n# ==== Pseudo-random card challenge (§6.2.2.1) ====")
print("INVOKER_AID =", hx(AID)); print("SEQ_COUNTER =", hx(SEQ))
print("PSEUDO_CHALLENGE_S8  =", hx(pseudo_card_challenge(KENC, 8,  SEQ, AID)))
print("PSEUDO_CHALLENGE_S16 =", hx(pseudo_card_challenge(KENC, 16, SEQ, AID)))

# PUT KEY payload: SCP03 encrypts new key under static DEK, AES-CBC zero-IV, no pad
# (block-multiple key) per Amd D §6.2.6.
newkey = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
enc = aes_cbc(KDEK, b"\x00"*16, newkey)
print("\n## PUT KEY (static DEK)")
print("NEW_KEY =", hx(newkey)); print("DEK =", hx(KDEK))
print("ENC_KEY_BLOCK =", hx(enc))
