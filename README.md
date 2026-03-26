# AES-128 CBC Implementation and Analysis

This project was developed for the **Applied Cryptography course**.

## Project Overview

This project implements the **AES-128 symmetric encryption algorithm from scratch** without using lookup tables or cryptographic libraries.

The system supports:

- AES-128 encryption
- AES-128 decryption
- CBC (Cipher Block Chaining) mode
- PKCS#7 padding
- Avalanche effect analysis

## AES Components Implemented

The following AES components were implemented manually:

- SubBytes / InvSubBytes
- ShiftRows / InvShiftRows
- MixColumns / InvMixColumns
- AddRoundKey
- Key Expansion

## CBC Mode

CBC mode was implemented to allow encryption of messages longer than one block.

Each plaintext block is XORed with the previous ciphertext block before encryption.

## Avalanche Effect Analysis

Two tests were performed:

1. Flipping one bit in the plaintext
2. Flipping one bit in the encryption key

Results showed about **50% bit difference in ciphertext**, confirming the strong avalanche property of AES.
