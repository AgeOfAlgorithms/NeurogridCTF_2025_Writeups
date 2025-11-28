#!/usr/bin/env python3
"""
Decrypt additional stones to get 624+ PRNG outputs
Author: AI Agent
Purpose: Decrypt stones 5-79 to get enough outputs for full PRNG recovery
Created: 2025-11-20
Expected result: Get 80 total stones = 640 PRNG outputs
Actual result: TBD
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
import json

START_STONE = 5
END_STONE = 80  # Decrypt up to stone 79 (inclusive)

stones_path = "/home/sean/ctf/NeurogridCTF_2025/Stones/crypto_stones/stones.txt"
line_length = 193

# Load existing decrypted stones
try:
    with open("decrypted_stones.json", "r") as f:
        decrypted_stones = json.load(f)
    print(f"[*] Loaded {len(decrypted_stones)} previously decrypted stones")
except:
    decrypted_stones = []
    print("[*] No previously decrypted stones found, starting from scratch")

NUM_TO_DECRYPT = END_STONE - START_STONE
print(f"[*] Decrypting stones {START_STONE} to {END_STONE-1} ({NUM_TO_DECRYPT} stones)")
print(f"[*] Estimated time: {NUM_TO_DECRYPT * 2} minutes (~{NUM_TO_DECRYPT * 2 / 60:.1f} hours)")
print()

start_overall = time.time()

for stone_idx in range(START_STONE, END_STONE):
    print(f"{'='*60}")
    print(f"[*] Decrypting stone {stone_idx} ({stone_idx - START_STONE + 1}/{NUM_TO_DECRYPT})...")

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

                    # Save after each successful decryption
                    with open("decrypted_stones.json", "w") as f:
                        json.dump(decrypted_stones, f, indent=2)

                    elapsed_overall = time.time() - start_overall
                    stones_done = stone_idx - START_STONE + 1
                    stones_remaining = NUM_TO_DECRYPT - stones_done
                    avg_time_per_stone = elapsed_overall / stones_done
                    eta_minutes = (stones_remaining * avg_time_per_stone) / 60

                    print(f"\n[+] Stone {stone_idx} decrypted in {elapsed:.1f}s")
                    print(f"    sigil_a: {sigil_a}")
                    print(f"    Progress: {stones_done}/{NUM_TO_DECRYPT} ({stones_done*100/NUM_TO_DECRYPT:.1f}%)")
                    print(f"    Elapsed: {elapsed_overall/60:.1f} min, ETA: {eta_minutes:.1f} min")
                    print()
                    found = True
                    break
        except:
            pass

    if not found:
        print(f"\n[-] WARNING: Stone {stone_idx} could not be decrypted!")
        break

total_elapsed = time.time() - start_overall
print(f"{'='*60}")
print(f"[+] Decryption complete!")
print(f"[+] Total stones: {len(decrypted_stones)}")
print(f"[+] Total time: {total_elapsed/60:.1f} minutes ({total_elapsed/3600:.2f} hours)")
print(f"[+] PRNG outputs: {len(decrypted_stones) * 8}")
print()

if len(decrypted_stones) * 8 >= 624:
    print(f"[+] Have {len(decrypted_stones) * 8} outputs - enough for MT19937 prediction!")
else:
    print(f"[!] Have {len(decrypted_stones) * 8} outputs - need {624 - len(decrypted_stones) * 8} more")
