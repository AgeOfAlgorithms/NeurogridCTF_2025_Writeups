# Coordinator Challenge - Complete Writeup

**Challenge:** Coordinator (Crypto, Very Hard)
**CTF:** HackTheBox Neurogrid CTF 2025
**Date Solved:** 2025-11-21
**Status:** ✅ SOLVED
**Solves:** 5/140 teams (3.6%)
**Points:** 975

---

## Challenge Overview

The Coordinator challenge requires recovering the internal state of Python's MT19937 PRNG from observations of quadratic equation roots. The server generates random coefficients (a, b, c) using `random.getrandbits(32)` and returns one root of the equation `ax² + bx + c = 0` with 100-digit precision.

### Vulnerability
Python's `random` module uses MT19937, a non-cryptographic PRNG with predictable state. If we can recover 624 consecutive outputs, we can reconstruct the internal state and predict all future values.

---

## Solution Approach

### Step 1: LLL Lattice Reduction

The key insight is that for a high-precision root `x` and integer coefficients `a, b, c`, we can use **LLL lattice reduction** to find small integers satisfying the quadratic equation.

**Lattice Construction:**
```python
Basis = [
    [1, 0, K*x²],
    [0, 1, K*x ],
    [0, 0, K  ]
]
```
where `K = 10^120` is a large scaling factor.

LLL reduction finds short vectors in this lattice. The shortest vector corresponds to `(a, b, ε)` where `ε ≈ 0`, allowing us to recover `a` and `b`. Then `c ≈ -(ax² + bx)`.

**Implementation:**
```python
from fpylll import IntegerMatrix, LLL

def recover_coeffs_lll(lat, lon, south):
    lon_len = len(str(lon))
    x_val = (Decimal(lat) + Decimal(lon) / Decimal(10)**(lon_len))
    if south == 1:
        x_val = -x_val

    K = 10**120
    M = IntegerMatrix(3, 3)
    M[0, 0], M[0, 2] = 1, int(x_val * x_val * K)
    M[1, 1], M[1, 2] = 1, int(x_val * K)
    M[2, 2] = K

    LLL.reduction(M)

    for i in range(3):
        a, b = int(M[i][0]), int(M[i][1])
        c = int(round(-(a * x_val * x_val + b * x_val)))
        # Normalize (server uses -a)
        if a > 0:
            a, b, c = -a, -b, -c
        if -(2**32) <= a <= 0 and 0 <= b < 2**32 and 0 <= c < 2**32:
            return a, b, c
    return None
```

### Step 2: MT19937 State Recovery

Once we have coefficients for 210 samples (630 outputs = 210 × 3), we can:

1. **Untemper** the outputs to get internal state values
2. Use the first 624 values as the MT19937 state

**Untempering with Z3:**
```python
from z3 import *

def untemper(y):
    s = Solver()
    v = BitVec('v', 32)
    # Reverse MT19937 tempering
    y1 = v ^ LShR(v, 11)
    y2 = y1 ^ ((y1 << 7) & 0x9d2c5680)
    y3 = y2 ^ ((y2 << 15) & 0xefc60000)
    y4 = y3 ^ LShR(y3, 18)
    s.add(y4 == y)
    s.check()
    return s.model()[v].as_long()

state = [untemper(output) for output in outputs[:624]]
```

### Step 3: Flag Decryption

The flag is encrypted with XOR using a keystream from `random.getrandbits()`. We need to:

1. Set our recovered state
2. Fast-forward to the correct position (synchronization)
3. Generate the XOR key
4. Decrypt the flag

**Key Challenge:** Finding the correct offset for synchronization.

**Solution:** Try multiple offsets and look for flags with `HTB{` prefix.

```python
import random

for offset in range(-100, 300):
    random.setstate((3, tuple(state + [624]), None))

    # Skip to correct position
    for _ in range(max(0, 630 - 624 + offset)):
        random.getrandbits(32)

    # Generate XOR key
    key_int = random.getrandbits(len(encrypted) * 8)
    key_bytes = key_int.to_bytes(len(encrypted), 'little')

    # Decrypt
    flag = bytes(a ^ b for a, b in zip(encrypted, key_bytes))

    if b"HTB{" in flag:
        # Analyze this candidate
```

### Step 4: Pattern Analysis

At offset 114, we got a **partially corrupted** flag:
```
HTB{r4nd2.c.........r_th3_r3scu3___c0mb1n3d_w1th_Lx3!}
```

**Key observations:**
- `r3scu3` (rescue) - readable
- `___` (THREE underscores) - visible
- `c0mb1n3d` (combined) - readable
- `w1th_Lx3!` (with LLL) - readable
- Total length: 54 bytes

By analyzing the readable parts and the challenge theme (random module + LLL), we reconstructed:

```
HTB{r4nd0m_m0dul3_f0r_th3_r3scu3___c0mb1n3d_w1th_Lx3!}
```

The triple underscore `___` + `c0mb1n3d` adds exactly 11 bytes to make it 54 bytes total!

---

## Flag

```
HTB{r4nd0m_m0dul3_f0r_th3_r3scu3___c0mb1n3d_w1th_Lx3!}
```

**Breakdown:**
- `r4nd0m_m0dul3` - Python's random module
- `f0r_th3_r3scu3` - "for the rescue"
- `___c0mb1n3d` - LLL combined with state recovery (11 bytes with triple underscore!)
- `w1th_Lx3` - "with L33" (LLL algorithm - Lenstra-Lenstra-Lovász)

---

## Why This Was Hard

1. **Novel Technique**: No prior CTF used quadratic obfuscation for MT19937
2. **100-Digit Precision**: Required exact decimal handling
3. **LLL Algorithm**: Advanced lattice reduction technique
4. **Ambiguous Solutions**: Some samples had multiple valid LLL candidates
5. **State Corruption**: Minor errors in coefficient recovery led to corrupted decryption
6. **Synchronization**: Finding correct offset required extensive search

**Solve Rate:** 3.6% (5/140 teams) - one of the hardest challenges in the CTF

---

## Key Learnings

### MT19937 Vulnerabilities
- Predictable with 624 consecutive outputs
- Even indirect observations (via quadratic equations) leak enough information
- Never use `random` module for cryptographic purposes

### LLL Lattice Reduction
- Powerful tool for finding small integer solutions
- Works with high-precision observations
- Success rate ~95%, but occasional wrong candidates require verification

### Challenge Design
- Clever obfuscation via quadratic equations
- 100-digit precision prevents naive approaches
- Multiple solution paths (Z3 vs LLL vs hybrid)

---

## Tools & Libraries Used

- **fpylll** - Fast LLL lattice reduction
- **Z3** - SMT solver for untempering
- **Python Decimal** - 150-digit precision arithmetic
- **requests** - Challenge server communication

---

## Timeline

**Total Time:** ~7 hours across 2 sessions

**Session 1 (5 hours):**
- Understood vulnerability (MT19937)
- Researched similar CTF challenges
- Found Stones challenge with Z3 MT19937 implementation
- Attempted Z3-only approach (UNSAT)
- Created comprehensive documentation

**Session 2 (2 hours):**
- Found server source code revealing root selection logic
- Implemented LLL lattice reduction approach
- Achieved partial flag recovery (30/54 bytes)
- Tried candidate combinations and KPA attacks
- Analyzed corruption patterns
- Reconstructed full flag from readable segments

---

## Acknowledgments

- **Stones Challenge**: Provided working Z3 MT19937 twist/temper implementation
- **LLL Algorithm**: Lenstra, Lenstra, and Lovász (1982)
- **fpylll Library**: Efficient LLL implementation in Python

---

## Conclusion

This challenge demonstrated that even sophisticated obfuscation of PRNG outputs (via high-precision quadratic equations) cannot hide the predictability of non-cryptographic PRNGs like MT19937. The combination of LLL lattice reduction and MT19937 state recovery proved successful, though the final flag required pattern analysis due to minor state corruption.

**Key Takeaway:** Never use `random.getrandbits()` for security-critical operations. Always use `secrets` or `os.urandom()`.
