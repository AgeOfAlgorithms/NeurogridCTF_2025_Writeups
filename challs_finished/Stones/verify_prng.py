#!/usr/bin/env python3
"""
Verify PRNG predictor training by checking against known stones
"""

import json
from mt19937predictor import MT19937Predictor

# Load decrypted stones
with open("decrypted_stones.json", "r") as f:
    decrypted_stones = json.load(f)

print(f"[*] Loaded {len(decrypted_stones)} decrypted stones")

# Train on first 70 stones (630 outputs)
TRAIN_COUNT = 70
chunks = []
for i in range(TRAIN_COUNT):
    stone = decrypted_stones[i]

    # sigil_a
    sigil_a = stone["sigil_a"]
    for j in range(4):
        chunk = (sigil_a >> (32 * j)) & 0xFFFFFFFF
        chunks.append(chunk)

    # sigil_b
    sigil_b = stone["sigil_b"]
    for j in range(4):
        chunk = (sigil_b >> (32 * j)) & 0xFFFFFFFF
        chunks.append(chunk)

    # echo
    chunks.append(stone["echo"])

print(f"[*] Training on {len(chunks)} outputs from stones 0-{TRAIN_COUNT-1}")

# Train predictor
predictor = MT19937Predictor()
for chunk in chunks:
    predictor.setrandbits(chunk, 32)

print(f"[*] Predictor trained!")
print()

# Now verify against stones 70-79
print(f"[*] Verifying against stones {TRAIN_COUNT}-79...")
print()

all_match = True
for i in range(TRAIN_COUNT, len(decrypted_stones)):
    stone = decrypted_stones[i]

    # Predict sigil_a
    predicted_a = 0
    for j in range(4):
        chunk = predictor.getrandbits(32)
        predicted_a |= (chunk << (32 * j))

    # Predict sigil_b
    predicted_b = 0
    for j in range(4):
        chunk = predictor.getrandbits(32)
        predicted_b |= (chunk << (32 * j))

    # Predict echo (get 32-bit, mask to 24)
    predicted_echo = predictor.getrandbits(32) & 0xFFFFFF

    # Check match
    match_a = (predicted_a == stone["sigil_a"])
    match_b = (predicted_b == stone["sigil_b"])
    match_echo = (predicted_echo == stone["echo"])

    symbol = "✓" if (match_a and match_b and match_echo) else "✗"

    print(f"Stone {i}: {symbol}")
    if not match_a:
        print(f"  sigil_a mismatch!")
        print(f"    Expected: {stone['sigil_a']}")
        print(f"    Got:      {predicted_a}")
    if not match_b:
        print(f"  sigil_b mismatch!")
        print(f"    Expected: {stone['sigil_b']}")
        print(f"    Got:      {predicted_b}")
    if not match_echo:
        print(f"  echo mismatch!")
        print(f"    Expected: {stone['echo']}")
        print(f"    Got:      {predicted_echo}")

    if not (match_a and match_b):
        all_match = False
        break

print()
if all_match:
    print("[+] All stones matched! PRNG predictor is working correctly!")
else:
    print("[!] Mismatch found! PRNG predictor is NOT working correctly!")
