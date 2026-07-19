#!/usr/bin/env python3
"""Independent SCP02 reference (GPCS v2.3.1 Appendix E, i=0x55) using
pyca/cryptography. Out-of-process oracle per impl-plan §10.2. The algorithm
mirrors GlobalPlatformPro (martinpaljak/GlobalPlatformPro) byte-for-byte:
GPCrypto.{mac_des_3des, mac_3des, des3_cbc, des_cbc, des_ecb, des3_ecb, pad80}
and SCP02Wrapper.wrap (variant 0x55: C-MAC on modified APDU, ICV encryption).
Emits flow KAT vectors that the Rust backend must reproduce byte-for-byte."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
B = default_backend()

def _tdes_key(k):           # pyca TripleDES: 8B => single-DES, 16B => EDE2
    return algorithms.TripleDES(k)

def des3_cbc(data, key, iv):     # DESede/CBC/NoPadding (16B key => EDE2)
    e = Cipher(_tdes_key(key), modes.CBC(iv), backend=B).encryptor()
    return e.update(data) + e.finalize()

def des_cbc(data, key, iv):      # DES/CBC/NoPadding, K1 only (first 8B)
    e = Cipher(_tdes_key(key[:8]), modes.CBC(iv), backend=B).encryptor()
    return e.update(data) + e.finalize()

def des_ecb(data, key):          # single-DES ECB, K1 only (ICV encryption)
    e = Cipher(_tdes_key(key[:8]), modes.ECB(), backend=B).encryptor()
    return e.update(data) + e.finalize()

def des3_ecb(data, key):         # DESede/ECB/NoPadding (KCV, PUT KEY)
    e = Cipher(_tdes_key(key), modes.ECB(), backend=B).encryptor()
    return e.update(data) + e.finalize()

def pad80(text, block=8):        # GPCrypto.pad80: ALWAYS adds (>=1 byte)
    total = (len(text)//block + 1) * block
    return text + b"\x80" + b"\x00"*(total - len(text) - 1)

def mac_3des(text, key, iv):     # full 3DES-CBC MAC, last 8 bytes (cryptograms)
    cg = des3_cbc(pad80(text, 8), key, iv)
    return cg[-8:]

def mac_des_3des(key, data, iv): # SCP02 Retail MAC (ISO 9797-1 Alg 3)
    d = pad80(data, 8)
    if len(d) > 8:
        des = des_cbc(d[:-8], key, iv)
        iv = des[-8:]
    cg = des3_cbc(d[-8:], key, iv)
    return cg[-8:]

# Session-key derivation constants (GPCS §E.4.1 / PlaintextKeys.SCP02_CONSTANTS)
C_ENC, C_MAC, C_RMAC, C_DEK = b"\x01\x82", b"\x01\x01", b"\x01\x02", b"\x01\x81"

def derive(base, const, seq):    # const(2) | seq(2) | 00*12, then 3DES-CBC, zero IV
    dd = const + seq + b"\x00"*12
    return des3_cbc(dd, base, b"\x00"*8)

class Scp02:
    def __init__(self, b_enc, b_mac, b_dek, host, card, seq, level):
        self.senc  = derive(b_enc, C_ENC,  seq)
        self.smac  = derive(b_mac, C_MAC,  seq)
        self.srmac = derive(b_mac, C_RMAC, seq)
        self.sdek  = derive(b_dek, C_DEK,  seq)
        self.host, self.card, self.seq, self.level = host, card, seq, level
        # GPCS v2.3.1 Appendix E.4.4: the cryptograms run over the 8-byte card
        # challenge = sequence_counter(2) || card_challenge(6). The earlier model
        # used host+card (14 bytes), dropping the counter; that matched a buggy
        # Rust impl but NOT real cards. Anchored to the JCOP 4 P71 trace below.
        card8 = seq + card
        self.card_crypto = mac_3des(host + card8, self.senc, b"\x00"*8)
        self.host_crypto = mac_3des(card8 + host, self.senc, b"\x00"*8)
        self.icv = None          # ICV before each command; None => first (EA)
        self.authed = False
        self.ricv = b"\x00"*8

    def wrap(self, apdu):
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        data = apdu[5:5+apdu[4]] if len(apdu) > 4 else b""
        # ICV: zero for first command (EA); des_ecb(prev, smac) thereafter.
        if self.icv is None:
            icv = b"\x00"*8
        else:
            icv = des_ecb(self.icv, self.smac)
        new_cla = cla | 0x04
        new_lc = len(data) + 8
        mac_in = bytes([new_cla, ins, p1, p2, new_lc]) + data
        cmac = mac_des_3des(self.smac, mac_in, icv)
        self.icv = cmac
        # C-ENC only after authentication and only if level sets C-DECRYPTION.
        if self.authed and (self.level & 0x02) and len(data) > 0:
            enc = des3_cbc(pad80(data, 8), self.senc, b"\x00"*8)
            new_lc = len(enc) + 8
            body = enc
        else:
            body = data
        if not self.authed:
            # GPCS v2.3.1 §E.3.2: the EA's own C-MAC becomes the ICV for
            # subsequent C-MAC verification *and/or R-MAC generation* — so the
            # R-MAC chaining value (ricv) is seeded from this EA cmac too, not
            # left at zero (previously a real conformance gap; see CHANGELOG
            # patch #10 / #11).
            self.ricv = cmac
            self.level_latched = p1
            self.authed = True
        return bytes([new_cla, ins, p1, p2, new_lc]) + body + cmac

    def encrypt_put_key(self, new_key):     # 3DES-ECB under session DEK
        return des3_ecb(new_key, self.sdek)

def kcv_3des(key):                          # des3_ecb(8x00)[0:3]
    return des3_ecb(b"\x00"*8, key)[:3]

# ---- Inputs: GP default double-length 3DES key 40..4F; seq 0001 ----
KEY  = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
HOST = bytes.fromhex("0001020304050607")        # 8-byte host challenge
CARD = bytes.fromhex("08090a0b0c0d")            # 6-byte card challenge
SEQ  = bytes.fromhex("0001")

def h(b): return b.hex()

print("# SCP02 KAT vectors (i=0x55), GP default key 40..4F, seq 0001")
print("KEY ", h(KEY)); print("HOST", h(HOST)); print("CARD", h(CARD)); print("SEQ ", h(SEQ))
s = Scp02(KEY, KEY, KEY, HOST, CARD, SEQ, 0x03)
print("S_ENC ", h(s.senc)); print("S_MAC ", h(s.smac))
print("S_RMAC", h(s.srmac)); print("S_DEK ", h(s.sdek))
print("CARD_CRYPTO", h(s.card_crypto))
print("HOST_CRYPTO", h(s.host_crypto))
print("KCV(base)", h(kcv_3des(KEY)))
print("KCV(S_ENC)", h(kcv_3des(s.senc)))

# EA wrap (level 0x03): 84 82 03 00 08 <host_crypto>
ea = bytes([0x84,0x82,0x03,0x00,0x08]) + s.host_crypto
print("EA_WRAPPED", h(s.wrap(ea)))
# Post-auth command with data (exercises C-ENC + C-MAC chaining + ICV-enc)
cmd = bytes.fromhex("80e60000050102030405")
print("CMD_WRAPPED", h(s.wrap(cmd)))
# A second post-auth command (further ICV-enc chaining)
cmd2 = bytes.fromhex("80e80000020102")
print("CMD2_WRAPPED", h(s.wrap(cmd2)))

# Level 0x01 (C-MAC only, no C-ENC): EA then command stay in plaintext.
s1 = Scp02(KEY, KEY, KEY, HOST, CARD, SEQ, 0x01)
ea1 = bytes([0x84,0x82,0x01,0x00,0x08]) + s1.host_crypto
print("EA1_WRAPPED", h(s1.wrap(ea1)))
print("CMD1_WRAPPED", h(s1.wrap(bytes.fromhex("80e60000050102030405"))))

# PUT KEY block: encrypt a 16-byte new 3DES key under session DEK (3DES-ECB)
NEWKEY = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
print("PUTKEY_ENC", h(s.encrypt_put_key(NEWKEY)))

# ---- R-MAC (level 0x13) round-trip, GPCS §E.4.4 (single-pad, spec-faithful) ----
# Command accumulation per wrap: CLA&~0x07, INS, P1, P2, then Lc‖data if present.
# R-MAC input: accumulated-command ‖ len(app_data) ‖ app_data ‖ SW, chained from
# the previous R-MAC (zero at session start), Retail-MAC'd under S-RMAC.
class Scp02Rmac(Scp02):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.rmac_cmd = b""
    def wrap(self, apdu):
        out = super().wrap(apdu)
        if self.authed and (self.level & 0x10):
            cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
            # §E.4.5: Lc is ALWAYS present (set to 0 for a case-1/2 no-data
            # command); command data follows. Mirrors the Rust accumulator.
            lc = apdu[4] if len(apdu) > 4 else 0
            data = apdu[5:5 + lc] if len(apdu) > 4 else b""
            self.rmac_cmd = bytes([cla & ~0x07, ins, p1, p2, len(data)]) + data
        return out
    def unwrap_rmac(self, app_data, sw):
        # build the R-MAC input and verify -> produces wire (app_data‖rmac‖sw)
        inp = self.rmac_cmd + bytes([len(app_data)]) + app_data + sw
        rmac = mac_des_3des(self.srmac, inp, self.ricv)
        self.ricv = rmac
        return rmac

s13 = Scp02Rmac(KEY, KEY, KEY, HOST, CARD, SEQ, 0x13)
ea13 = bytes([0x84,0x82,0x13,0x00,0x08]) + s13.host_crypto
s13.wrap(ea13)                                  # EA (not accumulated)
s13.wrap(bytes.fromhex("80ca006e00"))            # GET DATA-like post-auth command
app = bytes.fromhex("9f7f2a")                    # response app data
sw = bytes.fromhex("9000")
rmac = s13.unwrap_rmac(app, sw)
print("RMAC13_CMD", h(s13.rmac_cmd))
print("RMAC13_RESP_WIRE", h(app + rmac + sw))    # what the card would send
print("RMAC13_PLAIN", h(app + sw))               # expected unwrap output

# Case-1 (4-byte header, no Lc/Le): §E.4.5 mandates Lc=00 in the R-MAC block.
s13c = Scp02Rmac(KEY, KEY, KEY, HOST, CARD, SEQ, 0x13)
s13c.wrap(bytes([0x84, 0x82, 0x13, 0x00, 0x08]) + s13c.host_crypto)  # EA (excluded)
s13c.wrap(bytes.fromhex("80ca0066"))             # 4-byte case-1 post-auth command
app_c = bytes.fromhex("9f7f2a")
sw_c = bytes.fromhex("9000")
rmac_c = s13c.unwrap_rmac(app_c, sw_c)
print("RMAC13_CASE1_CMD", h(s13c.rmac_cmd))      # expect 80ca006600 (Lc=00 present)
print("RMAC13_CASE1_RESP_WIRE", h(app_c + rmac_c + sw_c))
print("RMAC13_CASE1_PLAIN", h(app_c + sw_c))

# ---- Hardware-anchored vector: NXP JCOP 4 P71 J3R150, SCP02 i=55 -------------
# Captured live with GlobalPlatformPro v25.10.20 (`gp -l -d`). The card's
# INITIALIZE UPDATE response carried CARD_CRYPTO; the EXTERNAL AUTHENTICATE that
# opened the channel carried HOST_CRYPTO + C-MAC. Both are reproduced here, which
# proves the sequence-counter fix end-to-end (cryptograms AND the EA C-MAC match
# the exact bytes the card accepted with 9000).
print()
print("# HARDWARE VECTOR (JCOP 4 P71, SCP02 i=55, gp v25.10.20)")
HW_ENC = bytes.fromhex("90379A3E7116D455E55F9398736A01CA")
HW_MAC = bytes.fromhex("473F36161A7F7F60CC3A766EA4BE5247")
HW_DEK = bytes.fromhex("D3749ED4FF42FD58B39EEB562B017CD9")
HW_HOST = bytes.fromhex("2572AE5C04A7C329")       # host challenge (IU command)
HW_CARD = bytes.fromhex("3A58BF1253D5")           # 6-byte card challenge (IU resp)
HW_SEQ  = bytes.fromhex("001C")                   # sequence counter (IU resp)
hw = Scp02(HW_ENC, HW_MAC, HW_DEK, HW_HOST, HW_CARD, HW_SEQ, 0x01)
print("HW_S_ENC      ", h(hw.senc))
print("HW_CARD_CRYPTO", h(hw.card_crypto), "(card sent BC5D5979580A581F)")
print("HW_HOST_CRYPTO", h(hw.host_crypto), "(EA   sent 079F403962F6CA28)")
hw_ea = bytes([0x84,0x82,0x01,0x00,0x08]) + hw.host_crypto
print("HW_EA_WRAPPED ", h(hw.wrap(hw_ea)), "(gp sent the same 21 bytes)")
assert h(hw.card_crypto) == "bc5d5979580a581f"
assert h(hw.host_crypto) == "079f403962f6ca28"
