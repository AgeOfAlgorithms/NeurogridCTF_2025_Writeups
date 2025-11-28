# Stones Challenge - Complete Writeup

## Challenge Information
- **Name:** Stones
- **Category:** Crypto
- **Difficulty:** Medium
- **Points:** 950
- **Solves:** 8
- **Flag:** `HTB{pyth0n_r4nd0m_1s_n0t_crypt0_s4f3}`

## Challenge Description
In the meditation halls of Saihō Temple, Rei discovers a chamber filled with sealed stones—each etched with twin markings that hum in rhythm. The monks say they were once used for communion between distant minds, a thousand messages waiting for the right voice to awaken them. Yet only one stone sings back when touched, and its song feels hauntingly familiar.

## Overview
This challenge involves recovering the internal state of Python's MT19937 PRNG (Mersenne Twister) from partial outputs to find a specific "stone" among 2^20 possibilities and decrypt a flag.

## Solution Summary

### The Approach
1. **Decrypt enough stones** to extract PRNG outputs (needed 130 stones)
2. **Use Z3 SMT solver** to recover full MT19937 state from partial outputs
3. **Simulate the PRNG** to find which stone contains target sigil_a
4. **Extract sigil_b** and decrypt flag

### Key Insight
The challenge's difficulty comes from `random.getrandbits(24)` returning only the **TOP 24 bits** of the 32-bit MT19937 output. The missing bottom 8 bits for each "echo" value must be recovered via constraint solving.

## Technical Details

### Stone Structure
Each stone contains:
- `sigil_a`: 128-bit value (4 × 32-bit PRNG calls, LSB-first)
- `sigil_b`: 128-bit value (4 × 32-bit PRNG calls, LSB-first)
- `echo`: 24-bit value (top 24 bits of 1 × 32-bit PRNG call)

### Encryption
Stones are encrypted with AES-ECB where:
- Key = `\x00` × 12 + `echo.to_bytes(4, 'big')`
- Search space per stone: 2^24 keys (~16 million)

### The Challenge
- Total stones: 2^20 (1,048,576)
- One stone contains our target `sigil_a`
- Need to find it, decrypt it, extract `sigil_b`, and decrypt flag

## Solution Steps

### Step 1: Stone Decryption (~2-2.5 hours)
Brute-force decrypt stones to extract PRNG outputs:
- Each stone takes ~2 minutes to decrypt (testing 2^24 keys at ~140k keys/sec)
- Needed 130 stones to provide enough constraints
- Total outputs: 130 stones × 9 outputs = 1,170 outputs

**Key files:**
- [decrypt_first_stones.py](decrypt_first_stones.py) - Initial 5 stones
- [decrypt_more_stones.py](decrypt_more_stones.py) - Batch decryption
- [all_decrypted_stones.json](all_decrypted_stones.json) - Final dataset

### Step 2: Z3 State Recovery (~30 minutes)
Use Z3 to solve for the 624 × 32-bit MT19937 internal state:

**Key constraints:**
```python
# For full outputs (sigil_a, sigil_b parts):
solver.add(temper(MT[k]) == known_value)

# For partial outputs (echo):
solver.add(LShR(temper(MT[k]), 8) == known_top_24_bits)
```

**Why 130 stones?**
- MT19937 performs "twist" operation every 624 outputs
- Missing 8 bits in echo values create constraint "holes"
- Need outputs spanning across twist boundary to fully constrain state
- 130 stones × 9 = 1,170 outputs > 624 × 2, ensuring coverage

**Key file:**
- [solve_stones_z3.py](solve_stones_z3.py) - Complete solution

### Step 3: Target Search (~5 minutes)
With recovered state:
1. Initialize Python's `random` with recovered state
2. Generate all 2^20 stones' sigil_a values
3. Find match: **Stone index 151,617**
4. Regenerate that stone's sigil_b: `183220215873312840422958718294835564770`

### Step 4: Flag Decryption
```python
key = sigil_b.to_bytes(16, 'big')
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(target_seal), 16)
# HTB{pyth0n_r4nd0m_1s_n0t_crypt0_s4f3}
```

## What Made This Difficult

1. **Bit Ordering Confusion**: Easy to assume `getrandbits(24)` returns bottom 24 bits (like masking), when it actually returns top 24 bits
2. **Data Requirements**: Need 130+ stones (not just 80) due to twist propagation
3. **Z3 Complexity**: Must correctly model MT19937's twist and temper operations symbolically
4. **Time Investment**: Decrypting 130 stones takes ~4 hours
5. **Constraint Solving**: Not a standard "crack it with tools" crypto problem

## Why Only 8 Solves?

This challenge requires:
- ✅ Recognizing it's a PRNG attack (not mathematical derivation)
- ✅ Understanding MT19937 internals (624 state, twist, temper)
- ✅ Knowing Python's random module returns MSB, not LSB
- ✅ Patience to decrypt 130+ stones (~4 hours)
- ✅ Z3 expertise to build correct symbolic model
- ✅ Debugging Z3 constraints when things don't work

Most solvers likely failed at:
- Thinking it's pure brute-force (2^44 combinations = infeasible)
- Trying mathematical relationships between sigil_a and stone index
- Using only 80 stones (not enough to constrain across twist)
- Incorrect Z3 implementation of temper/twist operations
- Wrong bit ordering assumption (TOP vs BOTTOM bits)

## Files

### Solution Files
- **`solve_stones_z3.py`** - Working Z3-based solution
- **`all_decrypted_stones.json`** - 130 decrypted stones dataset
- **`walkthrough.md`** - Official solution walkthrough

### My Attempt Files
- **`ATTEMPT.md`** - Documentation of PRNG attack approach
- **`WHAT_WENT_WRONG.md`** - Analysis of my critical mistake
- **`BLOCKERS.md`** - Progress tracking and blockers
- **`decrypted_stones.json`** - First 80 stones I decrypted

### Helper Scripts
- **`decrypt_first_stones.py`** - Initial stone decryption
- **`decrypt_more_stones.py`** - Batch stone decryption
- **`verify_prng.py`** - PRNG verification tests
- **`test_random_behavior.py`** - getrandbits() behavior tests

## Timeline

### My Attempt (4.5 hours)
- 2.5 hours: Decrypting 80 stones
- 0.5 hours: Testing and verification
- 1.0 hours: Failed brute-force attempts on missing bits
- 0.5 hours: Documentation

**Blocker:** Misunderstood which 8 bits were missing (thought TOP, actually BOTTOM)

### Correct Solution (2-3 hours)
- 2-2.5 hours: Decrypt 130 stones
- 0.5 hours: Z3 implementation and solving
- 0.1 hours: Target search and flag decryption

## Key Takeaways

1. **Always verify bit ordering** - MSB vs LSB assumptions can invalidate entire approaches
2. **Z3 is powerful** for partial-output PRNG state recovery
3. **Read the source** when documentation is unclear
4. **Test thoroughly** - verify not just behavior but exact bit positions
5. **MT19937 is predictable** but recovering state from partial outputs is non-trivial

## Flag
`HTB{pyth0n_r4nd0m_1s_n0t_crypt0_s4f3}`

The flag perfectly captures the lesson: Python's `random` module (MT19937) is NOT cryptographically secure and can be broken when outputs are observable!

---

**Status:** ✅ SOLVED (via external assistance after identifying correct approach)
**Difficulty:** 9/10 (Expert-level crypto + constraint solving + patience)
**Rating:** Excellent challenge design - rewards deep understanding of PRNGs
