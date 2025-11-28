#!/usr/bin/env python3
"""
Decrypt the first N stones to extract sigil_a values for PRNG state recovery
Author: AI Agent
Purpose: Extract PRNG outputs to recover internal state and find target stone
Created: 2025-11-20
Expected result: Get 10+ sigil_a values from first stones
Actual result: TBD

Strategy:
1. Decrypt first 10-20 stones (each takes ~2 min)
2. Use sigil_a values as PRNG outputs
3. Recover PRNG state with SMT solver
4. Fast-forward to find which stone has our target sigil_a
5. Decrypt only that stone
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
import json

NUM_STONES_TO_DECRYPT = 5

stones_path = "/home/sean/ctf/NeurogridCTF_2025/Stones/crypto_stones/stones.txt"
line_length = 193

decrypted_stones = []

print(f"[*] Decrypting first {NUM_STONES_TO_DECRYPT} stones to extract PRNG outputs")
print(f"[*] Estimated time: {NUM_STONES_TO_DECRYPT * 2} minutes")
print()

for stone_idx in range(NUM_STONES_TO_DECRYPT):
    print(f"{'='*60}")
    print(f"[*] Decrypting stone {stone_idx}...")

    with open(stones_path, "r") as f:
        f.seek(stone_idx * line_length)
        stone_hex = f.readline().strip()

    sealed_bytes = bytes.fromhex(stone_hex)
    expected_prefix = b"Stone #"
    start_time = time.time()
    checkpoint = time.time()

    found = False
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
                    sigil_a = int(parts[0].split(b"#")[1])
                    sigil_b = int(parts[1].split(b"#")[0])
                    elapsed = time.time() - start_time

                    stone_data = {
                        "index": stone_idx,
                        "echo": echo,
                        "sigil_a": sigil_a,
                        "sigil_b": sigil_b,
                        "time": elapsed
                    }
                    decrypted_stones.append(stone_data)

                    print(f"\n[+] Stone {stone_idx} decrypted in {elapsed:.1f}s")
                    print(f"    sigil_a: {sigil_a}")
                    print(f"    sigil_b: {sigil_b}")
                    print(f"    echo: {echo}")
                    print()
                    found = True
                    break
        except:
            pass

    if not found:
        print(f"\n[-] WARNING: Stone {stone_idx} could not be decrypted!")
        print(f"[-] This is unexpected and may indicate a problem")
        break

print(f"{'='*60}")
print(f"[+] Successfully decrypted {len(decrypted_stones)} stones")
print()

# Save to file for next step
output_file = "decrypted_stones.json"
with open(output_file, "w") as f:
    json.dump(decrypted_stones, f, indent=2)

print(f"[*] Saved decrypted stones to {output_file}")
print()
print("[*] Next step: Use these sigil_a values to recover PRNG state")
print(f"[*] sigil_a values for PRNG recovery:")
for stone in decrypted_stones:
    print(f"    Stone {stone['index']}: {stone['sigil_a']}")
