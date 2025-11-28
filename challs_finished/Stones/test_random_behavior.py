#!/usr/bin/env python3
"""
Test to understand Python's random.getrandbits() behavior
"""

import random
from mt19937predictor import MT19937Predictor

# Test 1: Verify getrandbits(128) decomposition
print("="*60)
print("Test 1: Verify getrandbits(128) == 4 × getrandbits(32)")
print("="*60)

random.seed(42)
val128 = random.getrandbits(128)

random.seed(42)
chunks = []
for i in range(4):
    chunks.append(random.getrandbits(32))

reconstructed = 0
for i, chunk in enumerate(chunks):
    reconstructed |= (chunk << (32 * i))

print(f"getrandbits(128): {val128}")
print(f"Reconstructed:    {reconstructed}")
print(f"Match: {val128 == reconstructed}")
print()

# Test 2: Check if getrandbits(24) consumes 32 bits
print("="*60)
print("Test 2: Does getrandbits(24) consume a full 32-bit output?")
print("="*60)

random.seed(42)
_ = random.getrandbits(24)  # Consume one getrandbits(24)
next_after_24 = random.getrandbits(32)

random.seed(42)
_ = random.getrandbits(32)  # Consume one getrandbits(32)
next_after_32 = random.getrandbits(32)

print(f"Next value after getrandbits(24): {next_after_24}")
print(f"Next value after getrandbits(32): {next_after_32}")
print(f"Same? {next_after_24 == next_after_32}")
print()

# Test 3: Try mt19937predictor with real sequence
print("="*60)
print("Test 3: Can predictor clone state from sequence?")
print("="*60)

random.seed(12345)
training_data = []
for i in range(624):
    training_data.append(random.getrandbits(32))

# Get next few values from real random
expected = []
for i in range(10):
    expected.append(random.getrandbits(32))

# Train predictor
predictor = MT19937Predictor()
for val in training_data:
    predictor.setrandbits(val, 32)

# Get predicted values
predicted = []
for i in range(10):
    predicted.append(predictor.getrandbits(32))

print("Expected values:")
for i, val in enumerate(expected):
    print(f"  {i}: {val}")

print("\nPredicted values:")
for i, val in enumerate(predicted):
    match = "✓" if val == expected[i] else "✗"
    print(f"  {i}: {val} {match}")

all_match = all(p == e for p, e in zip(predicted, expected))
print(f"\nAll match: {all_match}")
