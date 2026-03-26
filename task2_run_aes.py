# task2_run_aes.py
"""
Task # 2 
(Symmetric Crypto Systems: Implementation and Analysis)
"""

from __future__ import annotations
from task2_aes import hex_to_bytes, bytes_to_hex, aes_cbc_encrypt, aes_cbc_decrypt

BLOCK = 16  # AES block size in bytes

def read_hex(prompt: str, expected_len: int | None = None) -> bytes:
    """Read a hex string from the user, optionally enforcing a specific byte length."""
    while True:
        s = input(prompt).strip()
        try:
            b = hex_to_bytes(s)
            if expected_len is not None and len(b) != expected_len:
                print(f"Expected {expected_len} bytes ({expected_len*2} hex chars). Got {len(b)} bytes.")
                continue
            return b
        except Exception as e:
            print(f" Invalid hex: {e}")

def split_blocks(b: bytes, block_size: int = BLOCK) -> list[bytes]:
    """Split byte data into blocks of block_size."""
    return [b[i:i+block_size] for i in range(0, len(b), block_size)]

def print_blocks(label: str, b: bytes) -> None:
    """Print data in hex, grouped into labeled blocks."""
    blocks = split_blocks(b, BLOCK)
    print(f"{label} ({len(blocks)} block{'s' if len(blocks) != 1 else ''}):")
    for i, blk in enumerate(blocks, 1):
        print(f"  [{i:02d}] {bytes_to_hex(blk)}")
    if not blocks:
        print("  (none)")

def bits8(x: int) -> str:
  
    return format(x & 0xFF, "08b")

def compute_pkcs7_pad_len(n: int, block_size: int = BLOCK) -> int:
   
    r = n % block_size
    return block_size if r == 0 else (block_size - r)

def main():
    print("AES-128 CBC Runner")
    mode = input("Encrypt (E) or Decrypt (D): ").strip().upper()
    if mode not in {"E", "D"}:
        print(" Invalid mode. Use E or D.")
        return

    # Read key and IV from user
    key = read_hex("Enter 128-bit AES key: ", expected_len=16)
    iv  = read_hex("Enter 128-bit IV: ", expected_len=16)

    if mode == "E":
        # Read plaintext
        pt = read_hex("Enter plaintext: ")

        # Calculate padding details before encryption
        pad_len = compute_pkcs7_pad_len(len(pt), BLOCK)
        will_add_full_extra_block = (pad_len == BLOCK and (len(pt) % BLOCK) == 0)

        # Encrypt using CBC mode
        ct = aes_cbc_encrypt(key, iv, pt)

        # Show ciphertext blocks and padding info
        print_blocks("Ciphertext blocks (hex)", ct)
        print("\n[Padding info]")
        print(f"  Plaintext length: {len(pt)} bytes")
        print(f"  Padding length: {pad_len} byte(s)")
        print(f"  Padding byte value: 0x{pad_len:02x}  (bits: {bits8(pad_len)})")

        last_blk = ct[-BLOCK:]
        print(f"  Last ciphertext block: {bytes_to_hex(last_blk)}")
        if will_add_full_extra_block:
            print("  Extra padding block was added (plaintext was exact multiple of 16).")
            print("  Padding bits (repeated 16 times): " + " ".join(bits8(pad_len) for _ in range(16)))
        else:
            print(f"  Padding occupies the last {pad_len} byte(s) of the final block.")
            print("  Padding bits (one byte pattern): " + bits8(pad_len))

        # Show full ciphertext in one line all blocks
        print("\nRaw ciphertext (hex):")
        print(bytes_to_hex(ct))

    else:
        # Read ciphertext
        ct = read_hex("Enter ciphertext : ")
        if len(ct) % BLOCK != 0:
            print("Ciphertext length must be multiple of 16 bytes (32 hex chars per block).")
            return

        # Decrypt using CBC mode
        try:
            pt = aes_cbc_decrypt(key, iv, ct)
        except Exception as e:
            print(f"Decryption error: {e}")
            return

        # Show plaintext blocks
        print_blocks("Plaintext blocks (hex, after unpadding)", pt)
        print("\nRaw plaintext (hex):")
        print(bytes_to_hex(pt))
    

if __name__ == "__main__":
    main()
