# task2_aes_avalanche_analysis.py
from __future__ import annotations
import os, random
from typing import Tuple, List, Optional

from task2_aes import (
    aes_cbc_encrypt, aes_cbc_decrypt, bytes_to_hex,
    key_expansion, aes_decrypt_block, xor_bytes
)



def rand_bytes(n: int) -> bytes:
    return os.urandom(n)

def split_blocks(b: bytes, block_size: int = 16) -> List[bytes]:
    return [b[i:i+block_size] for i in range(0, len(b), block_size)]

def print_hex_blocks(label: str, b: bytes, block_size: int = 16) -> None:
    blocks = split_blocks(b, block_size)
    print(f"{label} ({len(blocks)} block{'s' if len(blocks)!=1 else ''}):")
    for i, blk in enumerate(blocks, 1):
        print(f"  [{i:02d}] {bytes_to_hex(blk)}")
    if not blocks:
        print("  (none)")

def bits_different(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("Equal lengths required")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def pct(x: float, total: float) -> float:
    return 100.0 * (x / total) if total else 0.0

def print_table(headers: List[str], rows: List[List[str]]) -> None:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    def fmt_row(vals: List[str]) -> str:
        return " | ".join(val.ljust(widths[i]) for i, val in enumerate(vals))
    line = "-+-".join("-" * w for w in widths)
    print(fmt_row(headers)); print(line)
    for r in rows:
        print(fmt_row(r))

def flip_one_bit(b: bytes, avoid_last_block: bool = False, block_size: int = 16) -> Tuple[bytes, int]:
    if not b:
        raise ValueError("Empty input")
    total_bits = len(b) * 8
    if not avoid_last_block or len(b) <= block_size:
        k = random.randrange(total_bits)
    else:
        usable_bits = (len(b) - block_size) * 8  
        k = random.randrange(usable_bits)
    byte_idx, bit_idx = divmod(k, 8)
    ba = bytearray(b)
    ba[byte_idx] ^= (1 << bit_idx)
    return bytes(ba), k

#Part C: Avalanche Effect CBC 10 rounds 

def run_avalanche_trials(trials: int = 10, blocks: int = 1, seed: Optional[int] = None) -> None:
    if seed is not None:
        random.seed(seed)

    P1 = rand_bytes(16 * blocks)  
    K1 = rand_bytes(16)
    IV = rand_bytes(16)

    C1 = aes_cbc_encrypt(K1, IV, P1)  
    total_bits = len(C1) * 8

    print("Avalanche Effect")


    # (a) Flip one bit in plaintext
    print("[A] Flip 1 bit in Plaintext (10 rounds)")
    diffs_A: List[int] = []; rows_A: List[List[str]] = []
    for t in range(trials):
        P1p, idx = flip_one_bit(P1)
        C2 = aes_cbc_encrypt(K1, IV, P1p)
        d = bits_different(C1, C2)
        diffs_A.append(d)
        rows_A.append([f"{t+1:02d}", f"{idx}", f"{d}", f"{pct(d, total_bits):.2f}%"])
        print(f"  Trial {t+1:02d}: flipped P bit #{idx}, Bits different = {d} ({pct(d, total_bits):.2f}%)")
    avg_A = sum(diffs_A) / len(diffs_A)
    print(f"Average bits different (A): {avg_A:.2f} / {total_bits} ({pct(avg_A, total_bits):.2f}%)\n")

    # (b) Flip one bit in key
    print("[B] Flip 1 bit in Key (10 rounds)")
    diffs_B: List[int] = []; rows_B: List[List[str]] = []
    for t in range(trials):
        K1p, idx = flip_one_bit(K1)
        C2 = aes_cbc_encrypt(K1p, IV, P1)
        d = bits_different(C1, C2)
        diffs_B.append(d)
        rows_B.append([f"{t+1:02d}", f"{idx}", f"{d}", f"{pct(d, total_bits):.2f}%"])
        print(f"  Trial {t+1:02d}: flipped K bit #{idx}, Bits different = {d} ({pct(d, total_bits):.2f}%)")
    avg_B = sum(diffs_B) / len(diffs_B)
    print(f"Average bits different (B): {avg_B:.2f} / {total_bits} ({pct(avg_B, total_bits):.2f}%)\n")

    print("Summary (A) Plaintext bit flip:"); print_table(
        headers=["Trial","Flipped bit idx (P)","Bits different","%"], rows=rows_A); print()
    print("Summary (B) Key bit flip:"); print_table(
        headers=["Trial","Flipped bit idx (K)","Bits different","%"], rows=rows_B); print()

# ------------------------------------------------------------------------------------------------------------------

def print_separator():
    print("-" * 69) 

# Part D (a): Bit error in ciphertext (CBC)

def manual_cbc_decrypt_no_unpad(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Manual CBC decryption (no PKCS#7 unpad) so we can display bytes even if corrupted/misaligned."""
    rks = key_expansion(key)
    out = []
    prev = iv
    for ct in split_blocks(ciphertext, 16):
        pt_block = aes_decrypt_block(ct, rks)
        out.append(xor_bytes(pt_block, prev))
        prev = ct
    return b"".join(out)

def cbc_bit_error_demo() -> None:
    print("CBC: Single-bit error in ciphertext")
    P = rand_bytes(48)  
    K = rand_bytes(16); IV = rand_bytes(16)
    C = aes_cbc_encrypt(K, IV, P)

    print_hex_blocks("Original plaintext blocks", P)
    print_hex_blocks("Original ciphertext blocks", C)

    C_mut, bit_idx = flip_one_bit(C, avoid_last_block=True)
    blk_idx = bit_idx // 128  
    print(f"\nFlipped ciphertext bit #{bit_idx} (in ciphertext block index {blk_idx})")

    try:
        P_dec = aes_cbc_decrypt(K, IV, C_mut)
    except Exception as e:
        print(f"[!] PKCS#7 padding failed after bit flip ({e}). Falling back to manual decrypt (no unpad).")
        P_dec = manual_cbc_decrypt_no_unpad(K, IV, C_mut)

    print_hex_blocks("\nDecrypted plaintext blocks after bit flip", P_dec)

    blocks_before = split_blocks(P)
    blocks_after  = split_blocks(P_dec[:len(blocks_before)*16])
    affected = [i for i,(b0,b1) in enumerate(zip(blocks_before, blocks_after)) if b0 != b1]

    print("\nAnalysis for CBC single-bit flip:")
    print(f"  Affected plaintext blocks: {', '.join(map(str,affected)) if affected else '(none)'}")
    if affected:
        if blk_idx < len(blocks_before):
            d0 = bits_different(blocks_before[blk_idx], blocks_after[blk_idx])
            print(f"  - Block {blk_idx}: heavily corrupted ({d0} bits differ out of 128).")
        if blk_idx + 1 < len(blocks_before):
            d1 = bits_different(blocks_before[blk_idx+1], blocks_after[blk_idx+1])
            print(f"  - Block {blk_idx+1}: ~1-bit error observed ({d1} bit(s) differ).")
        if blk_idx + 2 < len(blocks_before):
            ok = all(blocks_before[j] == blocks_after[j] for j in range(blk_idx+2, len(blocks_before)))
            print(f"  - Blocks {blk_idx+2}..end unaffected: {ok}")

# b: Loss of a ciphertext block (CBC) 

def cbc_block_loss_demo() -> None:
    print("CBC: Loss of a full ciphertext block")
    P = rand_bytes(64)  # 4 blocks of plaintext
    K = rand_bytes(16); IV = rand_bytes(16)
    C = aes_cbc_encrypt(K, IV, P)
    ct_blocks = split_blocks(C, 16)

    print_hex_blocks("Original ciphertext blocks", C)

    k = 1
    LOST = b"\x00" * 16
    ct_blocks_with_hole = ct_blocks[:]
    ct_blocks_with_hole[k] = None
    print(f"\nSimulated loss at ciphertext block index {k} ")

    rks = key_expansion(K)
    out_blocks = []
    prev = IV
    for i, ct in enumerate(ct_blocks_with_hole):
        if ct is None:
            out_blocks.append(b"\x00" * 16)
            prev = LOST
            continue
        pt_block = aes_decrypt_block(ct, rks)
        out_blocks.append(xor_bytes(pt_block, prev))
        prev = ct

    P_dec = b"".join(out_blocks)
    print_hex_blocks("\nDecrypted plaintext blocks", P_dec)

# c: Data exposure in ciphertext (image) 

def cbc_image_experiment(img_path: Optional[str] = None, out_prefix: str = "cbc_image_demo") -> None:
    print("CBC: Data Exposure image")
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return

    if img_path and os.path.exists(img_path):
        img = Image.open(img_path).convert("L")
        arr = np.array(img, dtype=np.uint8)
        print(f"Loaded image: {img_path}, shape={arr.shape}")
    else:
        n = 256; tile = 16
        arr = (np.indices((n, n)).sum(axis=0) // tile % 2).astype(np.uint8) * 255
        print("Generated 256x256 black/white checkerboard as our image before.")

    raw = arr.tobytes()
    K = rand_bytes(16); IV = rand_bytes(16)
    C = aes_cbc_encrypt(K, IV, raw)

    needed = arr.size
    ct_view = C[:needed] if len(C) >= needed else (C + bytes([0]) * (needed - len(C)))
    img_ct = Image.fromarray(
        __import__("numpy").frombuffer(ct_view, dtype="uint8").reshape(arr.shape),
        mode="L"
    )

    os.makedirs("out", exist_ok=True)
    img_plain_path = os.path.join("out", f"{out_prefix}_plain.png")
    img_ct_path    = os.path.join("out", f"{out_prefix}_cipher_visual.png")
    Image.fromarray(arr, mode="L").save(img_plain_path)
    img_ct.save(img_ct_path)

    print(f"  {img_plain_path}")
    print(f"  {img_ct_path}")



if __name__ == "__main__":
    run_avalanche_trials(trials=10, blocks=1)
    print_separator()
    print("Extended Analysis (CBC)\n")
    cbc_bit_error_demo()
    cbc_block_loss_demo()
    print_separator()
    cbc_image_experiment(img_path=None)
    print("Done.")
