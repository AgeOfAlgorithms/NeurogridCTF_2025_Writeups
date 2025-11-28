# Coordinator Challenge

**Category:** Crypto (Very Hard)
**CTF:** HackTheBox Neurogrid CTF 2025
**Status:** ✅ SOLVED
**Flag:** `HTB{r4nd0m_m0dul3_f0r_th3_r3scu3___c0mb1n3d_w1th_Lx3!}`
**Points:** 975
**Solves:** 5/140 teams (3.6%)
**Solve Date:** 2025-11-21

## Quick Summary

Successfully recovered MT19937 PRNG state from observations of quadratic equation roots using **LLL lattice reduction** combined with **Z3 untempering**. The challenge required 100-digit precision arithmetic and pattern analysis to reconstruct the flag from partially corrupted decryption.

## Solution Overview

1. **Collect Samples**: Gathered 220 samples from `/read-star-coordinates`
2. **LLL Lattice Reduction**: Recovered (a,b,c) coefficients from 100-digit quadratic roots
3. **State Recovery**: Used Z3 to untemper 624 MT19937 outputs to reconstruct internal state
4. **Flag Decryption**: Generated XOR keystream and decrypted flag
5. **Pattern Analysis**: Reconstructed full flag from partially corrupted decryption at offset 114

## Key Files

### Solution
- **[WRITEUP_FINAL.md](WRITEUP_FINAL.md)** - Complete technical writeup with full methodology
- **[analyze_corruption.py](analyze_corruption.py)** - Final solver that found the flag pattern
- **[samples_fresh.json](samples_fresh.json)** - 220 fresh samples from final solve

### Reference Materials
- **[ATTEMPT.md](ATTEMPT.md)** - Early Z3-only attempt documentation
- **[SESSION_SUMMARY.md](SESSION_SUMMARY.md)** - Debugging session notes
- **[solve_coordinator_lll.py](solve_coordinator_lll.py)** - Reference LLL implementation
- **[verify_state.py](verify_state.py)** - MT19937 state consistency checker

### Challenge Source
- **[solve_coordinator_z3.py](solve_coordinator_z3.py)** - Original Z3-only approach (UNSAT)
- **[test_root_selection.py](test_root_selection.py)** - Server root selection mechanism

## The Challenge

### Endpoints
- `GET /read-star-coordinates` → Returns `{lat, lon, south}` encoding a quadratic root
- `GET /invoke-synchro` → Returns XOR-encrypted flag

### Vulnerability
Server uses Python's `random.getrandbits()` (MT19937 PRNG) which is predictable with 624 consecutive outputs.

### Obfuscation
- Server generates: `a = -random.getrandbits(32)`, `b = random.getrandbits(32)`, `c = random.getrandbits(32)`
- Computes roots of `ax² + bx + c = 0` with 100-digit precision
- Returns one root based on value of `b`
- Root encoded as `{lat: integer_part, lon: decimal_digits, south: sign_bit}`

## Key Insights

### LLL Lattice Reduction
Given a high-precision root `x`, construct lattice basis:
```
[1, 0, K·x²]
[0, 1, K·x ]
[0, 0, K  ]
```
where K = 10^120. LLL reduction finds short vectors `(a, b, ε)` where `ε ≈ 0`, recovering integer coefficients.

### Pattern Analysis
The flag was partially corrupted but offset 114 revealed the pattern:
```
HTB{r4nd2.c.........r_th3_r3scu3___c0mb1n3d_w1th_Lx3!}
```
Readable segments: `r3scu3`, `___` (three underscores), `c0mb1n3d`, `w1th_Lx3!`
Combined with challenge theme → full 54-byte flag

## Quick Start

```bash
# Run the final solver
conda activate ctf
python analyze_corruption.py

# View comprehensive writeup
cat WRITEUP_FINAL.md

# Verify state recovery approach
python verify_state.py
```

## Why This Was Hard

1. **Novel Technique**: First CTF to use quadratic obfuscation for MT19937
2. **100-Digit Precision**: Required exact Decimal arithmetic
3. **LLL Algorithm**: Advanced lattice reduction technique
4. **Ambiguous Solutions**: ~5% of samples had multiple valid candidates
5. **State Corruption**: Minor errors propagated through MT19937 twist
6. **Pattern Recognition**: Final flag required manual reconstruction

**Solve Rate:** 3.6% (5/140 teams) - one of the hardest challenges in the CTF

## Tools Used

- **fpylll** - Fast LLL lattice reduction
- **Z3** - SMT solver for MT19937 untempering
- **Python Decimal** - 150-digit precision arithmetic
- **requests** - Challenge server communication

---

*For full technical details, see [WRITEUP_FINAL.md](WRITEUP_FINAL.md)*
