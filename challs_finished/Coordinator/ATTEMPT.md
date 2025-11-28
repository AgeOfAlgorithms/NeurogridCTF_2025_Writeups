# Coordinator Challenge - Attempt Report

**Challenge:** Coordinator (Crypto, Very Hard)
**CTF:** HackTheBox Neurogrid CTF 2025
**Date:** 2025-11-21
**Status:** NOT SOLVED
**Solves:** 3 teams / 130 teams (2.3% solve rate)

---

## Executive Summary

This challenge requires recovering the internal state of Python's MT19937 PRNG from observations of quadratic equation roots. Despite significant progress in understanding the vulnerability and implementing multiple solution approaches, the challenge remains unsolved due to fundamental precision and computational complexity issues.

**Key Discovery:** Found server source code revealing that root selection is based on coefficient `b`, which was not initially considered.

**Main Blocker:** Z3 solver cannot efficiently handle the combination of:
1. 100-digit precision numbers (from lat/lon encoding)
2. Multiple candidate solutions per sample (5+ candidates)
3. Non-linear quadratic constraints

---

## Challenge Analysis

### Server Implementation
Located source at: `/home/sean/ctf/NeurogridCTF_2025/archive/Coordinator/crypto_coordinator/`

```python
def magic(a, b, c):
    decimal.getcontext().prec = 100
    D = decimal.Decimal(b**2 - 4*a*c)
    x1 = (-b + D.sqrt()) / (2*a)
    x2 = (-b - D.sqrt()) / (2*a)
    assert all(a*x**2 + b*x + c < 1e-9 for x in [x1, x2])
    return x1 if b < (2**31 + 2**32)//2 else x2  # KEY INSIGHT!

def observe_constellation():
    while True:
        a, b, c = -draw_cosmic_pattern(32), draw_cosmic_pattern(32), draw_cosmic_pattern(32)
        x = magic(a, b, c)
        if x != None:
            return x

def draw_cosmic_pattern(b):
    return secure_getrandbits(b)  # Uses random.getrandbits -> MT19937!
```

**Vulnerability:** Python's `random` module uses MT19937, a non-cryptographic PRNG

### Data Format
- Endpoint: `/read-star-coordinates`
- Returns: `{lat: int, lon: int, south: 0|1}`
- Encoding: `x = (-1)^south * (lat + lon / 10^len(str(lon)))`
- Precision: ~88-100 decimal digits preserved

### Endpoints
1. `/read-star-coordinates` - Returns quadratic root
2. `/invoke-synchro` - Returns XOR-encrypted flag

---

## Approaches Attempted

### 1. Z3 with Float Precision + OR Constraints
**File:** [solve_coordinator_z3.py](solve_coordinator_z3.py:1)

**Approach:**
- Convert lat/lon to float (loses precision to ~15 significant digits)
- Use Z3 Real/Int to find (a,b,c) candidates per sample
- Find 5+ candidates per sample
- Build Z3 model with MT19937 twist/temper (from Stones challenge)
- Use OR constraints: "at least one candidate must be correct"

**Results:**
- 50 samples: SAT in 0.6s (insufficient for 624-word state)
- 210 samples: **UNSAT** (no solution exists)

**Why It Failed:**
- Float conversion loses precision → finds many spurious low-coefficient solutions
- Example: For x ≈ -0.514, finds (a=-2, b=1, c=1) which gives x=-0.5, not x=-0.514027430053858...
- Real MT19937 outputs are 32-bit (billions), not small integers
- UNSAT because none of the candidates are the actual MT19937 outputs

### 2. Z3 with Exact Rational Arithmetic
**File:** [solve_coordinator_rational.py](solve_coordinator_rational.py:1)

**Approach:**
- Preserve full precision using Z3's Real type
- Represent x = lat + lon/(10^digits) exactly as rational
- Add constraint: `a*x² + b*x + c == 0` (exact equality)

**Result:** **TIMEOUT** after 180+ seconds

**Why It Failed:**
- Z3 struggles with the quadratic constraint when x is a complex rational
- The solver must search the space of (a ∈ [-2^32,0], b,c ∈ [0,2^32])
- Non-linear constraint (quadratic) + huge search space = intractable

### 3. Integer Arithmetic via Denominator Clearing
**File:** [solve_coordinator_direct.py](solve_coordinator_direct.py:1)

**Approach:**
- If x = p/q, then ax² + bx + c = 0 becomes: a*p² + b*p*q + c*q² = 0
- This is an integer equation (no divisions!)
- Use Z3 BitVec for integer arithmetic

**Result:** **NOT VIABLE**

**Why It Failed:**
```
Sample 0:
  p (numerator): 99 digits
  q (denominator): 100 digits

Example: p² ≈ 2^660 (way beyond BitVec(32) which holds 2^32)
```
- The numbers involved are 100+ digits
- Z3 BitVec(32) can only hold 32-bit values
- Would need BitVec(1000+) which is computationally infeasible

### 4. Root Selection Filter
**Discovery:** Server chooses root based on `b`:
```python
return x1 if b < 3221225472 else x2
```

**Attempt:** Add filter to candidate finding:
- Calculate both roots (x1, x2)
- Check which root the server would return
- Only keep candidates where observed x matches selected root

**Result:** Zero candidates found (even with tolerance 0.5)

**Why It Failed:**
- The float-precision candidates don't satisfy even the loose root selection criterion
- This confirms that float precision is insufficient

---

## Key Findings

### 1. Precision Requirements
- Server uses `decimal.getcontext().prec = 100` (100-digit arithmetic)
- Lat/lon encoding preserves ~88-100 digits
- Float64 only provides ~15 significant digits
- **Loss of ~85 digits of precision** when converting to float

### 2. The Multi-Candidate Problem
For any observed x (with limited precision), there exist multiple (a,b,c) solutions:
- Z3 easily finds 5-10 candidates per sample
- But these are LOW-COEFFICIENT approximations (a~1-10, b~1-10, c~1-10)
- Real MT19937 outputs are 32-BIT values (up to 4 billion)
- With full precision, there would likely be only 1 solution in the MT19937 range

### 3. Comparison to Stones Challenge
The Stones challenge (successfully solved) had:
- **Direct observations**: Top 24 bits of MT output (bottom 8 unknown)
- **Single candidate**: Each observation has exactly 1 value (the observed bits)
- **Linear constraints**: Known_bits(temper(MT[i])) == observed_value

Coordinator has:
- **Indirect observations**: Roots of quadratic with MT outputs as coefficients
- **Multiple candidates**: Each observation has 5+ mathematically valid solutions
- **Non-linear constraints**: Quadratic equation must be satisfied

### 4. Computational Complexity
The challenge combines three hard problems:
1. **Non-linear constraints** (quadratic equations)
2. **High-precision arithmetic** (100-digit numbers)
3. **Large search space** (2^32 values for a,b,c each)

Z3 can handle any TWO of these, but not all THREE simultaneously.

---

## Why This Challenge Is Hard

### Mathematical Perspective
Given x (with precision ε), find (a,b,c) such that:
- a ∈ [-2^32, -1]
- b, c ∈ [0, 2^32-1]
- |ax² + bx + c| < ε

For small ε (full precision), this likely has 0-1 solutions.
For large ε (float precision), this has infinitely many solutions.

We have large ε (float precision) but need to find the solution in a specific range (MT19937 outputs).

### CTF Perspective
- **Solve rate:** 2.3% (3/130 teams)
- **Category:** Crypto, Very Hard
- **Novel technique:** No known CTF challenges use quadratic root obfuscation for MT19937

The low solve rate suggests either:
1. An advanced mathematical technique is required (lattice reduction, Coppersmith, etc.)
2. There's a completely different attack vector we haven't considered
3. Extreme computational resources are needed

---

## Files Created

### Analysis & Documentation
- `RESEARCH_FINDINGS.md` - Survey of similar CTF challenges
- `BREAKTHROUGH.md` - Discovery of Stones challenge as template
- `FINAL_STATUS.md` - Previous status report (before finding source code)
- `ATTEMPT.md` - This file

### Solution Attempts
- `solve_coordinator_z3.py` - Main Z3 approach with float precision (UNSAT)
- `solve_coordinator_rational.py` - Exact rational arithmetic (TIMEOUT)
- `solve_coordinator_direct.py` - Integer arithmetic via clearing denominators (NOT VIABLE)

### Testing & Debugging
- `test_root_selection.py` - Verified server's root selection logic
- `test_negative_a.py` - Explored negative a handling
- `debug_sample_0.py` - Deep dive into candidate finding for first sample
- `find_candidates_bruteforce.py` - Attempted random search (impractical)

### Data Collection
- `collect_many_samples.py` - Collected 250 samples
- `samples.json` - 250 samples from challenge server

---

## Potential Next Steps (For Future Attempts)

### 1. Alternative Mathematical Approaches
- **Lattice reduction (LLL):** Model as a lattice problem
- **Coppersmith's method:** Polynomial roots modulo known factors
- **Gröbner bases:** System of polynomial equations
- **Continued fractions:** Approximate x with rational to reduce precision needs

### 2. Computational Approaches
- **Distributed Z3:** Split problem across multiple solvers/machines
- **GPU acceleration:** Parallelize candidate search
- **Hybrid approach:** Use Z3 for small subsets, then merge solutions

### 3. Different Attack Vectors
- **State space reduction:** Exploit properties of MT19937 to reduce search space
- **Partial state recovery:** Recover some state bits, brute-force the rest
- **Side channels:** Look for timing attacks or other info leakage

### 4. Revisit Assumptions
- **Are all samples needed?:** Maybe a clever subset is sufficient
- **Is state recovery necessary?:** Perhaps flag can be decrypted differently
- **Is there metadata we're missing?:** HTTP headers, timing info, etc.

---

## Lessons Learned

1. **Precision matters:** CTF crypto challenges can hinge on numerical precision
2. **Source code is gold:** Finding the server implementation revealed the root selection mechanism
3. **Solver limitations:** Z3 is powerful but not magic - some problems are inherently hard
4. **Novel techniques:** Hardest challenges require creative approaches beyond standard tools
5. **Time management:** Knowing when to move on vs. persist is important in CTF

---

## Conclusion

This challenge demonstrates sophisticated understanding of:
- PRNG cryptanalysis
- Constraint solving
- Numerical precision issues
- Mathematical optimization

While unsolved, significant progress was made in understanding the problem space and identifying the fundamental barriers to a Z3-based solution. The challenge likely requires either:
1. A mathematical insight we haven't discovered
2. Extreme computational resources
3. A completely different attack angle

**Recommendation:** Move on to other solvable challenges and potentially return with fresh perspective or new techniques discovered elsewhere in the CTF.

---

## Appendix: Server Source Code

### shrine.py
```python
from random import getrandbits as secure_getrandbits
import decimal

def magic(a, b, c):
    decimal.getcontext().prec = 100
    D = decimal.Decimal(b**2 - 4*a*c)
    x1 = (-b + D.sqrt()) / (2*a)
    x2 = (-b - D.sqrt()) / (2*a)
    assert all(a*x**2 + b*x + c < 1e-9 for x in [x1, x2])
    return x1 if b < (2**31 + 2**32)//2 else x2

def observe_constellation():
    while True:
        a, b, c = -draw_cosmic_pattern(32), draw_cosmic_pattern(32), draw_cosmic_pattern(32)
        x = magic(a, b, c)
        if x != None:
            return x
        else:
            return -1337.1337

def draw_cosmic_pattern(b):
    return secure_getrandbits(b)

bind = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
```

###app.py
```python
@app.route('/read-star-coordinates', methods=['GET'])
def read_star_coordinates():
    val = shrine.observe_constellation()
    r, d = list(map(int, str(val).split('.')))
    return jsonify({
        'south': int(val < 0),
        'lat': abs(r),
        'lon': int(d)
    }), 200

@app.route('/invoke-synchro', methods=['GET'])
def invoke_synchro():
    chant = int.to_bytes(shrine.draw_cosmic_pattern(len(SCROLL)*8), length=len(SCROLL), byteorder='little')
    echo = shrine.bind(chant, SCROLL)
    return jsonify({'echo': echo.hex()}), 200
```
