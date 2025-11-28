# Stones Challenge - PRNG State Recovery Attempt

## Challenge Information
- **Challenge Name:** Stones
- **Category:** Crypto
- **Difficulty:** Medium (975 points, 3 solves)
- **Attempt Date:** 2025-11-20
- **Status:** BLOCKED (PRNG state recovery failed due to missing echo bits)

---

## Summary

This attempt focused on **MT19937 PRNG state recovery** as the solution approach, successfully decrypting 80 stones (640+ PRNG outputs) but encountering a critical blocker: the `echo` values use `random.getrandbits(24)` which internally consumes a full 32-bit MT19937 output but only returns the bottom 24 bits. The missing top 8 bits prevent accurate PRNG state reconstruction.

**Time invested:** ~3 hours
**Stones decrypted:** 80/1,048,576 (0.0076%)
**PRNG outputs extracted:** 720 (80 stones × 9 outputs, including echo)
**Next step:** Brute-force the missing 8 bits per echo value

---

## The Solution Approach: MT19937 PRNG Attack

### Core Vulnerability

Python's `random.seed()` uses **MT19937 (Mersenne Twister)**, a PRNG that:
- Has internal state of 624 × 32-bit words
- Is **completely predictable** from 624 consecutive 32-bit outputs
- Can be cloned using tools like `mt19937predictor`
- Allows fast-forwarding to predict any future/past value

### Attack Strategy

Instead of brute-forcing 2^44 combinations (2^20 stones × 2^24 keys), recover the PRNG state:

**Phase 1: Extract PRNG Outputs**
- Decrypt first 78+ stones (minimum 624 ÷ 8 = 78 stones needed)
- Each stone provides outputs from: `sigil_a` (4×32-bit), `sigil_b` (4×32-bit), `echo` (1×32-bit)
- Total: 9 outputs per stone, but echo is problematic (explained below)

**Phase 2: Recover PRNG State**
- Feed 624+ consecutive 32-bit values to mt19937predictor
- This clones the entire MT19937 internal state
- Time: < 1 second

**Phase 3: Find Target Stone**
- Fast-forward the cloned PRNG through 2^20 stones
- Compare predicted `sigil_a` values against target
- Identify exact stone index containing target
- Time: ~30 seconds

**Phase 4: Decrypt Target Stone**
- Brute-force only that one stone (2^24 keys)
- Extract `sigil_b` and decrypt flag
- Time: ~2 minutes

**Total theoretical time: ~3 hours** (vs 1400 days for full brute force = **7200x speedup**)

---

## Implementation Details

### Python's getrandbits() Structure

Testing revealed (`test_prng_structure.py`) that:

1. **getrandbits(128) uses LSB-first ordering:**
   ```python
   # getrandbits(128) is equivalent to:
   result = 0
   for i in range(4):
       chunk = getrandbits(32)
       result |= (chunk << (32 * i))  # LSB first!
   ```

2. **getrandbits(24) consumes a full 32-bit output:**
   ```python
   random.seed(42)
   _ = random.getrandbits(24)  # Consumes 32 bits internally
   next_val = random.getrandbits(32)

   # This gives SAME next_val as:
   random.seed(42)
   _ = random.getrandbits(32)  # Also consumes 32 bits
   next_val = random.getrandbits(32)
   ```

### PRNG Output Extraction

From each decrypted stone:
```python
# Stone format: "Stone #{sigil_a}:{sigil_b}#"
# Convert sigil_a and sigil_b to 32-bit chunks (LSB first)

chunks = []
for value in [sigil_a, sigil_b]:
    for i in range(4):
        chunk = (value >> (32 * i)) & 0xFFFFFFFF
        chunks.append(chunk)

# Echo: only bottom 24 bits available, top 8 bits unknown
chunks.append(echo)  # This is the problem!
```

---

## What Was Accomplished

### ✅ Successfully Completed

1. **Decrypted 80 stones** (5 initially, then 75 more in background)
   - Time: ~2.5 hours total
   - Speed: ~140,000 keys/second
   - Output: `decrypted_stones.json` (80 entries)

2. **Extracted 720 PRNG outputs**
   - 640 full 32-bit outputs from sigil_a and sigil_b
   - 80 partial 24-bit outputs from echo (problematic)

3. **Verified getrandbits() behavior**
   - Confirmed LSB-first ordering for getrandbits(128)
   - Confirmed getrandbits(24) consumes 32 bits internally
   - Confirmed mt19937predictor works with full 32-bit sequences

4. **Installed and tested mt19937predictor**
   ```bash
   pip install git+https://github.com/kmyk/mersenne-twister-predictor.git
   ```

### Scripts Created

- **`decrypt_first_stones.py`** - Decrypted stones 0-4 (40 outputs)
- **`decrypt_more_stones.py`** - Decrypted stones 5-79 in background
- **`test_prng_structure.py`** (or `test_random_behavior.py`) - Verified getrandbits() internals
- **`final_get_flag.py`** - Full PRNG recovery and flag extraction (blocked)
- **`verify_prng.py`** - Tested predictor accuracy (revealed blocker)
- **`verify_prng_no_echo.py`** - Confirmed predictions work WITHOUT echo

---

## The Critical Blocker: Missing Echo Bits

### The Problem

From `source.py`:
```python
echo = random.getrandbits(24)  # Returns 24-bit value
```

**What happens internally:**
1. MT19937 generates a full 32-bit output
2. Python masks it to 24 bits: `output & 0xFFFFFF`
3. We only see the bottom 24 bits
4. Top 8 bits are lost forever

**Impact on PRNG state recovery:**
- mt19937predictor needs ALL consumed 32-bit outputs
- Missing 8 bits per echo = 256 possibilities per echo
- With 78 echoes: 256^78 ≈ 10^187 combinations (infeasible)

### Verification

Created `verify_prng.py` to test predictor accuracy:
```python
# Train on stones 0-69 (630 outputs including echo)
# Try to predict stones 70-79
```

**Result:**
- Stone 70: ✗ sigil_a mismatch
- Predictions immediately diverge
- Confirming that partial echo values break state recovery

Created `verify_prng_no_echo.py`:
```python
# Train on stones 0-69 WITHOUT echo (560 outputs)
# Cannot predict stone 70 because PRNG advanced 70 positions
```

**Conclusion:**
- We NEED the echo values for proper state tracking
- But adding 24-bit echo values breaks the predictor
- Classic partial-output PRNG attack problem

---

## Why Only 3 Solves?

This challenge required:
1. **Recognizing** it's a PRNG attack (not mathematical index derivation)
2. **Knowing** MT19937 is predictable from 624 outputs
3. **Understanding** how Python's `getrandbits()` works internally
4. **Having patience** to decrypt 78+ stones (~2.5 hours)
5. **Solving** the partial-output problem (missing 8 bits per echo)

Most solvers likely:
- Tried mathematical approaches and failed (as we did initially)
- Gave up before discovering PRNG vulnerability
- Or didn't solve the partial-output problem

---

## Attempted Solutions

### ❌ Approach 1: Include echo as-is (24-bit)
```python
predictor.setrandbits(echo, 32)  # Wrong: missing top 8 bits
```
**Result:** State recovery fails, predictions don't match

### ❌ Approach 2: Skip echo entirely
```python
# Don't include echo in training
```
**Result:** PRNG position tracking wrong (70 echoes consumed = 70 position offset)

### ❌ Approach 3: Pad echo with zeros
```python
predictor.setrandbits(echo & 0xFFFFFF, 32)  # Same as approach 1
```
**Result:** Same failure as approach 1

---

## Possible Solutions Going Forward

### Option 1: Brute-Force Missing 8 Bits (RECOMMENDED)

For each echo value, there are only 256 possibilities for the top 8 bits:
```python
for top_bits in range(256):
    full_echo = (top_bits << 24) | echo
    # Try PRNG recovery with this full_echo
```

**Complexity:**
- 256 possibilities per echo position
- But we can verify correctness by checking if predictions match known stones
- Can use stones 70-79 as verification set
- Once we find correct top bits for echoes 0-69, we have full state!

**Estimated time:** Unknown, depends on search strategy

### Option 2: SMT Solver (Z3)

Use tools like RNGeesus (Z3-based PRNG state recovery):
```python
# Define constraints for MT19937 state
# Known bottom 24 bits of each echo
# Solve for top 8 bits that produce matching outputs
```

**References:**
- [RNGeesus](https://github.com/deut-erium/RNGeesus) - SMT PRNG attacks
- Can handle partial outputs with constraints

### Option 3: Lattice-Based Cryptanalysis

MT19937 has known lattice-based attacks for partial outputs:
- Requires mathematical expertise
- May work with 24 out of 32 bits known
- Research papers exist on this topic

---

## Files Created

### Core Scripts
- `decrypt_first_stones.py` - Initial 5 stones (40 outputs)
- `decrypt_more_stones.py` - Stones 5-79 background decryption
- `final_get_flag.py` - Full recovery script (blocked by echo issue)
- `verify_prng.py` - Predictor accuracy test (revealed blocker)
- `verify_prng_no_echo.py` - Test without echo values
- `test_random_behavior.py` - getrandbits() behavior verification

### Documentation
- `SOLUTION_APPROACH.md` - Complete methodology and analysis
- `BLOCKERS.md` - Updated with PRNG breakthrough and current blocker
- `README.md` - Challenge overview
- `ATTEMPT.md` - This file

### Data
- `decrypted_stones.json` - 80 decrypted stones with sigil_a, sigil_b, echo

---

## Key Technical Insights

1. **MT19937 is predictable** from 624 consecutive 32-bit outputs
2. **getrandbits(128)** internally calls getrandbits(32) four times, LSB-first
3. **getrandbits(24)** consumes a full 32-bit MT19937 output internally
4. **Partial outputs** (24 out of 32 bits) break standard mt19937predictor
5. **Missing 8 bits** = 256 possibilities (brute-forceable per echo)
6. **Stone decryption** averages ~90 seconds per stone (~140k keys/sec)

---

## Comparison to Previous Attempts

### Before PRNG Discovery
- Tested 13 mathematical index derivations (all failed)
- Used SageMath for prime factorization analysis
- Concluded computational infeasibility (1400 days)
- **Estimated time:** 1400 days for full brute force

### After PRNG Discovery
- Decrypted 80 stones (~2.5 hours)
- Extracted 720 PRNG outputs
- Discovered partial-output blocker
- **Progress:** 7200x faster approach, but blocked at final step

---

## Resources Used

### Tools & Libraries
- **pycryptodome** - AES decryption (`pip install pycryptodome`)
- **mt19937predictor** - PRNG state recovery
  ```bash
  pip install git+https://github.com/kmyk/mersenne-twister-predictor.git
  ```

### References
- [MT19937 Predictor GitHub](https://github.com/kmyk/mersenne-twister-predictor)
- [RNGeesus - SMT PRNG Attacks](https://github.com/deut-erium/RNGeesus)
- [Practical CTF - PRNG Attacks](https://book.jorianwoltjer.com/cryptography/pseudo-random-number-generators-prng)
- [Mersenne Twister Wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister)

---

## Current Status

**Attempt Status:** BLOCKED but very close to solution
**Blocker:** Missing 8 bits per echo value prevents PRNG state recovery
**Next Step:** Implement brute-force approach for missing 8 bits

**Files ready for cleanup:**
- Old attempt scripts from initial mathematical approaches
- Various test scripts

**Time Breakdown:**
- Stone decryption: ~2.5 hours
- Testing and verification: ~0.5 hours
- **Total:** ~3 hours invested in this attempt

---

## Recommendations

1. **Implement Option 1 (Brute-Force 8 Bits)** - Most straightforward
   - For each echo position, try all 256 top-bit values
   - Use stones 70-79 as verification set
   - Once correct bits found, full state recovered

2. **If Option 1 fails, try Option 2 (Z3/SMT solver)**
   - Tools like RNGeesus are designed for this exact problem
   - More complex but handles partial outputs natively

3. **Consider distributed approach**
   - 256^78 is infeasible, but smart search with verification is not
   - Can parallelize across different echo positions

---

## Lessons Learned

### For CTF Solving
- **Not all crypto is mathematical** - Sometimes it's implementation flaws
- **PRNG attacks are powerful** - 624 is the magic number for MT19937
- **Partial outputs are a known problem** - Missing bits break recovery
- **Patience matters** - 2.5 hours of decryption to get data
- **Verify assumptions** - Testing getrandbits() behavior was crucial

### For Challenge Design
- This is **extremely well-designed**:
  - Requires PRNG knowledge (not common)
  - Requires patience (2.5+ hours minimum)
  - Requires solving partial-output problem
  - Only 3 solves confirms perfect difficulty
  - At the edge of feasibility for skilled players

---

## Conclusion

This attempt successfully identified the correct solution approach (MT19937 PRNG state recovery) and executed it up to the critical blocker: missing 8 bits per echo value. The approach is sound and would work if we had full 32-bit echo values.

**The challenge is solvable** - just needs one more step: recovering the missing 8 bits through brute-force verification or SMT solving.

**Estimated time to complete:** Unknown, but likely within reach given we're this close.

---

**Attempt Date:** 2025-11-20
**Status:** To be continued with brute-force approach
**Files:** See `decrypted_stones.json` for extracted data
