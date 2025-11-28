#!/usr/bin/env python3
"""
Verify PRNG predictor training WITHOUT echo values
"""

import json
from mt19937predictor import MT19937Predictor

# Load decrypted stones
with open("decrypted_stones.json", "r") as f:
    decrypted_stones = json.load(f)

print(f"[*] Loaded {len(decrypted_stones)} decrypted stones")

# Train on first 70 stones (560 outputs, NO echo)
TRAIN_COUNT = 70
chunks = []
for i in range(TRAIN_COUNT):
    stone = decrypted_stones[i]

    # sigil_a (4 outputs)
    sigil_a = stone["sigil_a"]
    for j in range(4):
        chunk = (sigil_a >> (32 * j)) & 0xFFFFFFFF
        chunks.append(chunk)

    # sigil_b (4 outputs)
    sigil_b = stone["sigil_b"]
    for j in range(4):
        chunk = (sigil_b >> (32 * j)) & 0xFFFFFFFF
        chunks.append(chunk)

    # NO echo!

print(f"[*] Training on {len(chunks)} outputs (NO echo) from stones 0-{TRAIN_COUNT-1}")
print(f"[!] Warning: Only {len(chunks)} outputs, need 624 for full state recovery")
print()

# Train predictor
predictor = MT19937Predictor()
for chunk in chunks:
    predictor.setrandbits(chunk, 32)

print(f"[*] Predictor trained!")
print()

# Now try to predict stone 70 (but account for echo gaps)
stone_70 = decrypted_stones[70]

print(f"[*] Trying to predict stone 70...")
print(f"[*] Note: We don't know the echo values for stones 0-69, so there are gaps")
print()

# The predictor is trained on the first 560 outputs (no echo)
# But in reality, there were 70 echo values consumed between those outputs
# So the real PRNG state has advanced 560 + 70 = 630 positions
# But our predictor thinks it's at position 560

# This means we can't directly predict stone 70 without knowing the echo values

print("[!] Cannot verify without echo values - predictor has wrong state!")
print()
print("[*] This means we NEED the echo values for proper state recovery")
print("[*] But adding 24-bit echo values breaks the predictor...")
print()
print("[*] Possible solutions:")
print("    1. Use Z3/SMT solver that can handle missing bits")
print("    2. Brute-force the missing top 8 bits of each echo")
print("    3. Find a different attack vector")
