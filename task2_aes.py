# task2_aes.py
from __future__ import annotations
from typing import List


IRR_POLY = 0x11B  # AES polynomial: x^8 + x^4 + x^3 + x + 1 


def gf_xtime(a: int) -> int:
    a &= 0xFF
    a <<= 1
    if a & 0x100:  # reduce by irreducible polynomial if more than 8
        a ^= IRR_POLY
    return a & 0xFF


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = gf_xtime(a)
        b >>= 1
    return res & 0xFF


def gf_pow(a: int, e: int) -> int:
    a &= 0xFF
    r = 1
    while e:
        if e & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        e >>= 1
    return r & 0xFF


def gf_inv(a: int) -> int:
    a &= 0xFF
    if a == 0:
        return 0
    return gf_pow(a, 254)



def _affine_transform(x: int) -> int:
    c = 0x63
    y = 0
    for i in range(8):
        bit = (
            ((x >> i) & 1)
            ^ ((x >> ((i + 4) & 7)) & 1)
            ^ ((x >> ((i + 5) & 7)) & 1)
            ^ ((x >> ((i + 6) & 7)) & 1)
            ^ ((x >> ((i + 7) & 7)) & 1)
            ^ ((c >> i) & 1)
        )
        y |= (bit << i)
    return y & 0xFF


def build_sboxes() -> tuple[bytes, bytes]:
    sbox = [0] * 256
    invs = [0] * 256
    for b in range(256):
        inv_b = gf_inv(b)
        s = _affine_transform(inv_b)
        sbox[b] = s
    for x, s in enumerate(sbox):
        invs[s] = x
    return bytes(sbox), bytes(invs)


SBOX, INV_SBOX = build_sboxes()



def bytes_to_state(block16: bytes) -> List[int]:
    """Return state as flat 16-byte list in AES column-major order (index = 4*col + row)."""
    assert len(block16) == 16
    return list(block16)


def state_to_bytes(state: List[int]) -> bytes:
    assert len(state) == 16
    return bytes(b & 0xFF for b in state)



# Round functions -->AES steps

def sub_bytes(state: List[int]) -> None:
    for i in range(16):
        state[i] = SBOX[state[i]]


def inv_sub_bytes(state: List[int]) -> None:
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def shift_rows(state: List[int]) -> None:
    for r in range(4):
        row = [state[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]  #left rotate by r
        for c in range(4):
            state[4 * c + r] = row[c]


def inv_shift_rows(state: List[int]) -> None:
    for r in range(4):
        row = [state[4 * c + r] for c in range(4)]
        if r:
            row = row[-r:] + row[:-r]  #right rotate by r
        for c in range(4):
            state[4 * c + r] = row[c]


def mix_single_column(col: List[int]) -> List[int]:
    a0, a1, a2, a3 = col
    return [
        gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3,
        a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3,
        a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3),
        gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2),
    ]


def inv_mix_single_column(col: List[int]) -> List[int]:
    a0, a1, a2, a3 = col
    return [
        gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9),
        gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13),
        gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11),
        gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14),
    ]


def mix_columns(state: List[int]) -> None:
    for c in range(4):
        col = [state[4 * c + r] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            state[4 * c + r] = mixed[r]


def inv_mix_columns(state: List[int]) -> None:
    for c in range(4):
        col = [state[4 * c + r] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            state[4 * c + r] = mixed[r]


def add_round_key(state: List[int], round_key: bytes) -> None:
    assert len(round_key) == 16
    for i in range(16):
        state[i] ^= round_key[i]



# Key expansion 

def rot_word(w: bytes) -> bytes:
    return bytes([w[1], w[2], w[3], w[0]])


def sub_word(w: bytes) -> bytes:
    return bytes([SBOX[b] for b in w])


def rcon_iter(n: int) -> List[bytes]:
    out: List[bytes] = []
    r = 0x01
    for _ in range(n):
        out.append(bytes([r, 0x00, 0x00, 0x00]))
        r = gf_mul(r, 0x02)
    return out


def key_expansion(key16: bytes) -> List[bytes]:
    assert len(key16) == 16
    Nb, Nk, Nr = 4, 4, 10
    w: List[bytes] = [key16[i:i+4] for i in range(0, 16, 4)]
    rcons = rcon_iter(Nr)
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = bytes(x ^ y for x, y in zip(sub_word(rot_word(temp)), rcons[(i // Nk) - 1]))
        w.append(bytes(x ^ y for x, y in zip(w[i - Nk], temp)))
    # pack round keys (11 * 16 bytes)
    round_keys = []
    for r in range(Nr + 1):
        round_keys.append(b"".join(w[4*r:4*r+4]))
    return round_keys


def aes_encrypt_block(block16: bytes, round_keys: List[bytes]) -> bytes:
    assert len(block16) == 16 and len(round_keys) == 11
    state = bytes_to_state(block16)
    add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def aes_decrypt_block(block16: bytes, round_keys: List[bytes]) -> bytes:
    assert len(block16) == 16 and len(round_keys) == 11
    state = bytes_to_state(block16)
    add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[rnd])
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)



# Hex helper functions

def hex_to_bytes(s: str) -> bytes:
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 != 0:
        raise ValueError("Hex string length must be even")
    return bytes.fromhex(s)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


# CBC mode and Padding
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Bad PKCS#7 padding")
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("Key and IV must be 16 bytes each")
    rks = key_expansion(key)
    pt = pkcs7_pad(plaintext, 16)
    out = []
    prev = iv
    for i in range(0, len(pt), 16):
        blk = xor_bytes(pt[i:i+16], prev)
        ct = aes_encrypt_block(blk, rks)
        out.append(ct)
        prev = ct
    return b"".join(out)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-128-CBC."""
    if len(key) != 16 or len(iv) != 16 or (len(ciphertext) % 16) != 0:
        raise ValueError("Key/IV invalid or ciphertext not multiple of block size")
    rks = key_expansion(key)
    out = []
    prev = iv
    for i in range(0, len(ciphertext), 16):
        ct = ciphertext[i:i+16]
        blk = aes_decrypt_block(ct, rks)
        out.append(xor_bytes(blk, prev))
        prev = ct
    return pkcs7_unpad(b"".join(out), 16)


