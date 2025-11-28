# Stones Challenge

## Challenge Information
- **Challenge Name:** Stones
- **Category:** Crypto
- **Difficulty:** Medium
- **Points:** 950
- **Solves:** 8
- **Start Time:** 2025-11-20
- **Status:** ✅ SOLVED
- **Flag:** `HTB{pyth0n_r4nd0m_1s_n0t_crypt0_s4f3}`

## Description
In the meditation halls of Saihō Temple, Rei discovers a chamber filled with sealed stones-each etched with twin markings that hum in rhythm. The monks say they were once used for communion between distant minds, a thousand messages waiting for the right voice to awaken them. Yet only one stone sings back when touched, and its song feels hauntingly familiar.

## Files

### Challenge Files
- `crypto_stones/source.py` - Challenge source code
- `crypto_stones/oracle.txt` - Given values (sigil_a and encrypted flag)
- `crypto_stones/stones.txt` - 2^20 encrypted stones (193MB)

### Tools Created
- `stone_index_tester.py` - Optimized stone tester (~140k keys/sec, configurable)
- `analyze_sigil.py` - SageMath analysis tool for factorization

### Documentation
- **`WRITEUP.md`** ⭐ - Complete solution writeup
- **`WHAT_WENT_WRONG.md`** - Analysis of my critical mistake
- **`walkthrough.md`** - Official solution walkthrough
- `ATTEMPT.md` - My PRNG attack approach documentation
- `BLOCKERS.md` - Historical progress tracking
- `SOLUTION_APPROACH.md` - Methodology analysis
- `README.md` - This file

## Challenge Mechanics
1. 2^20 (1,048,576) stones are generated, each with random sigil_a and sigil_b values
2. Each stone is AES-ECB encrypted with a 24-bit key (weak key: 12 zero bytes + 4 random bytes)
3. One stone contains our target sigil_a value
4. We need to find that stone, brute-force its key, extract sigil_b, and decrypt the flag

## Solution Summary

**Status: ✅ SOLVED** - MT19937 PRNG state recovery via Z3

### The Approach
1. ✅ **Decrypted 130 stones** (~1170 PRNG outputs extracted)
2. ✅ **Used Z3 SMT solver** to recover MT19937 internal state from partial outputs
3. ✅ **Simulated PRNG** to find target stone at index 151,617
4. ✅ **Extracted sigil_b** and decrypted flag

### The Key Insight
`random.getrandbits(24)` returns the **TOP 24 bits** of the 32-bit MT19937 output, not the bottom 24 bits. The missing bottom 8 bits must be recovered via constraint solving (Z3).

### Why This Was Hard
1. **Bit ordering confusion** - Easy to assume bottom bits, not top bits
2. **Data requirements** - Need 130+ stones, not just 80, due to MT19937 twist operation
3. **Z3 complexity** - Must correctly model twist and temper operations symbolically
4. **Time investment** - Decrypting 130 stones takes ~4 hours
5. **Only 8 solves** - Expert-level crypto + constraint solving required

### What I Did Wrong
I correctly identified the PRNG attack approach and decrypted 80 stones, but I assumed `getrandbits(24)` returned the **bottom** 24 bits when it actually returns the **top** 24 bits. This single bit-ordering mistake invalidated all my brute-force attempts.

See [WHAT_WENT_WRONG.md](WHAT_WENT_WRONG.md) for detailed analysis.

### Files
- **`solve_stones_z3.py`** - Working Z3 solution
- **`all_decrypted_stones.json`** - 130 stones dataset
- **`WRITEUP.md`** - Complete writeup with technical details
