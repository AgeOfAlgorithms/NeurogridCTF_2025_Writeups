#!/usr/bin/env python3
"""
Final flag extraction using PRNG state recovery
Author: AI Agent
Purpose: Recover PRNG, find target stone, decrypt flag
Created: 2025-11-20
Expected result: HTB{...}
Actual result: TBD

This is the final step after decrypting 78+ stones.
"""

import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from mt19937predictor import MT19937Predictor
import time

# Target values from oracle.txt
target_sigil_a = 215467030496758327356459851529799063230
seal = bytes.fromhex("eb5dbac62b1d25df756d848972fd091a63f88471e2ebffa01cea7b611f5f42920662684e80ae7e3ba0978aafe91e7d4e")

print("="*60)
print("STONES CHALLENGE - FINAL FLAG EXTRACTION")
print("="*60)
print()

# Load decrypted stones
print("[*] Loading decrypted stones...")
with open("decrypted_stones.json", "r") as f:
    decrypted_stones = json.load(f)

num_stones = len(decrypted_stones)
num_outputs = num_stones * 8

print(f"[+] Loaded {num_stones} stones ({num_outputs} PRNG outputs)")
print()

if num_outputs < 624:
    print(f"[!] ERROR: Need 624 outputs, only have {num_outputs}")
    print(f"[!] Decrypt {(624 - num_outputs) // 8} more stones")
    exit(1)

# Extract PRNG outputs
print("[*] Extracting PRNG outputs from stones...")
chunks = []
for stone in decrypted_stones:
    # Extract from sigil_a (LSB first)
    sigil_a = stone["sigil_a"]
    for i in range(4):
        chunk = (sigil_a >> (32 * i)) & 0xFFFFFFFF
        chunks.append(chunk)

    # Extract from sigil_b (LSB first)
    sigil_b = stone["sigil_b"]
    for i in range(4):
        chunk = (sigil_b >> (32 * i)) & 0xFFFFFFFF
        chunks.append(chunk)

    # Include echo (24-bit value, but getrandbits(24) consumed a full 32-bit output)
    # We only have the bottom 24 bits, top 8 bits were masked off
    # Add it anyway - the predictor might still work
    echo = stone["echo"]
    chunks.append(echo)

print(f"[+] Extracted {len(chunks)} outputs")
print()

# Recover PRNG state
print("[*] Recovering MT19937 PRNG state...")
start_time = time.time()

predictor = MT19937Predictor()
for chunk in chunks:
    predictor.setrandbits(chunk, 32)

elapsed = time.time() - start_time
print(f"[+] PRNG state recovered in {elapsed:.3f}s!")
print()

# Find target stone
print("[*] Searching for target stone...")
print(f"[*] Target sigil_a: {target_sigil_a}")
print()

start_time = time.time()
found_index = None

# We trained on stones 0-79, so predictor is now at stone 80
# Search from stone 80 onwards
START_STONE = len(decrypted_stones)

for stone_idx in range(START_STONE, 2**20):
    if stone_idx % 50000 == 0:
        elapsed = time.time() - start_time
        percent = stone_idx * 100 / (2**20)
        print(f"[*] Checking stone {stone_idx:7d} / 1048576 ({percent:5.1f}%)")

    # Predict sigil_a (4 × 32-bit, LSB first)
    predicted_sigil_a = 0
    for i in range(4):
        chunk = predictor.getrandbits(32)
        predicted_sigil_a |= (chunk << (32 * i))

    # Skip sigil_b (4 × 32-bit)
    for i in range(4):
        predictor.getrandbits(32)

    # Skip echo (getrandbits(24) consumes one full 32-bit output internally)
    predictor.getrandbits(32)

    if predicted_sigil_a == target_sigil_a:
        found_index = stone_idx
        break

elapsed = time.time() - start_time

if found_index is None:
    print()
    print("[!] ERROR: Target sigil_a not found!")
    print("[!] PRNG state recovery may have failed")
    print("[!] Possible issues:")
    print("    - Not enough outputs (need 624+)")
    print("    - Incorrect LSB/MSB ordering")
    print("    - Echo handling mismatch")
    exit(1)

print()
print("="*60)
print(f"[+] TARGET STONE FOUND!")
print(f"[+] Stone index: {found_index}")
print(f"[+] Search time: {elapsed:.1f}s")
print("="*60)
print()

# Save the index
with open("target_stone_index.txt", "w") as f:
    f.write(str(found_index))
print(f"[*] Saved index to target_stone_index.txt")
print()

# Decrypt the target stone
print("[*] Decrypting target stone...")
print(f"[*] This will take ~2 minutes (2^24 keys to try)")
print()

stones_path = "crypto_stones/stones.txt"
line_length = 193

with open(stones_path, "r") as f:
    f.seek(found_index * line_length)
    stone_hex = f.readline().strip()

sealed_bytes = bytes.fromhex(stone_hex)
expected_prefix = b"Stone #"

start_time = time.time()
checkpoint = time.time()

for echo in range(2**24):
    if echo % 1000000 == 0 and echo > 0:
        elapsed = time.time() - checkpoint
        rate = 1000000 / elapsed
        remaining = (2**24 - echo) / rate
        print(f"[*] Progress: {echo:,}/{2**24:,} ({echo*100/2**24:.1f}%) - {rate:,.0f} keys/sec - ETA: {remaining:.0f}s")
        checkpoint = time.time()

    key = b"\x00" * 12 + echo.to_bytes(4, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(sealed_bytes)

    if plaintext[0:7] != expected_prefix:
        continue

    try:
        unpadded = unpad(plaintext, 16)
        if b":" in unpadded:
            parts = unpadded.split(b":")
            if len(parts) == 2:
                found_a = int(parts[0].split(b"#")[1])
                if found_a == target_sigil_a:
                    found_b = int(parts[1].split(b"#")[0])
                    elapsed = time.time() - start_time

                    print()
                    print("="*60)
                    print(f"[+] Stone decrypted in {elapsed:.1f}s!")
                    print(f"[+] sigil_a: {found_a}")
                    print(f"[+] sigil_b: {found_b}")
                    print(f"[+] echo: {echo}")
                    print("="*60)
                    print()

                    # Decrypt the flag
                    print("[*] Decrypting flag...")
                    key_flag = found_b.to_bytes(16, byteorder='big')
                    cipher_flag = AES.new(key_flag, AES.MODE_ECB)
                    flag = unpad(cipher_flag.decrypt(seal), 16)

                    print()
                    print("="*60)
                    print("="*60)
                    print(f"[+] FLAG: {flag.decode()}")
                    print("="*60)
                    print("="*60)

                    # Save flag
                    with open("flag.txt", "w") as f:
                        f.write(flag.decode())

                    print()
                    print("[+] Flag saved to flag.txt")
                    print()
                    print("[+] Challenge solved! 🎉")
                    exit(0)
    except:
        pass

print()
print("[!] ERROR: Could not decrypt target stone!")
print("[!] This shouldn't happen if the index is correct")
