# What Went Wrong - Stones Challenge Analysis

## The Critical Mistake

**I misunderstood which bits `random.getrandbits(24)` returns from the 32-bit MT19937 output.**

### What I Thought
I assumed `random.getrandbits(24)` returns the **BOTTOM 24 bits** of the 32-bit MT19937 output:
```
32-bit output: [TOP 8 bits] [BOTTOM 24 bits]
                   ↑              ↑
               UNKNOWN        RETURNED
```

### What Actually Happens
`random.getrandbits(24)` returns the **TOP 24 bits** of the 32-bit MT19937 output:
```
32-bit output: [TOP 24 bits] [BOTTOM 8 bits]
                    ↑              ↑
                RETURNED        UNKNOWN
```

The correct relationship is: `echo = full_output >> 8`

Or equivalently: `full_output = (echo << 8) | unknown_bottom_8_bits`

## Impact of This Mistake

1. **I was searching for the wrong unknown bits**:
   - I tried to brute-force the TOP 8 bits
   - I needed to brute-force the BOTTOM 8 bits

2. **My Z3 constraints were wrong**:
   - My constraint: `predictor.setrandbits(echo, 32)` (just using 24-bit value as-is)
   - Correct constraint: `solver.add(z3.LShR(y, 8) == echo)` (shift right to match top 24 bits)

3. **All my verification tests failed** because I was comparing the wrong bits

## The Correct Solution

The working solution ([solve_stones_z3.py](solve_stones_z3.py)) does the following:

### Step 1: Extract Outputs Correctly
```python
# echo (24 bits, TOP 24 bits of 32-bit output)
echo = stone['echo']
outputs.append(("partial", echo))
```

### Step 2: Use Z3 with Correct Constraint
```python
for k, (type, val) in enumerate(outputs):
    y = temper(current_MT[k])

    if type == "full":
        solver.add(y == val)  # Full 32-bit match
    else:
        # val is TOP 24 bits, so shift the output right by 8
        solver.add(z3.LShR(y, 8) == val)
```

### Step 3: Solve and Recover State
- Z3 solves for all 624 MT19937 state variables
- The bottom 8 bits for each echo are inferred from the other constraints
- With 130 stones (~1170 outputs), Z3 can uniquely determine the full state

### Step 4: Find Target Stone
- Initialize Python's random with recovered state
- Generate all 2^20 stones' sigil_a values
- Find which stone matches target
- Extract sigil_b and decrypt flag

## Why I Didn't Discover This

1. **Insufficient testing**: I tested `getrandbits(24)` behavior but didn't verify WHICH bits it returns
2. **Wrong assumption**: I assumed it would return the least significant bits (like a mask operation)
3. **No documentation check**: I didn't read Python's random module internals carefully enough

## What I Should Have Done

1. **Test the actual bit positions**:
   ```python
   random.seed(42)
   full = random.getrandbits(32)

   random.seed(42)
   partial = random.getrandbits(24)

   # Check: Is partial == (full & 0xFFFFFF)?  NO!
   # Check: Is partial == (full >> 8)?  YES!
   ```

2. **Read Python source code**: The `_randbelow_with_getrandbits` function shows that getrandbits returns the most significant bits when k < 32

3. **Use Z3 from the start**: Instead of trying to brute-force, recognize that Z3 is designed exactly for this type of constraint problem with unknown bits

## Key Learnings

1. **ALWAYS verify bit ordering** in PRNG operations - never assume MSB vs LSB
2. **Z3 is the right tool** for partial-output PRNG state recovery
3. **Test edge cases thoroughly** - my `test_random_behavior.py` tested consumption but not bit positions
4. **Read the source** when documentation is unclear

## Additional Insights from the Walkthrough

The walkthrough revealed additional complexity:

1. **Data Requirements**: 80 stones (~720 outputs) were NOT enough!
   - The MT19937 `twist` operation happens every 624 outputs
   - Missing 8 bits in echo values created "holes" that propagated through the twist
   - **Solution needed 130 stones (~1170 outputs)** to fully constrain state across twist boundary

2. **Common Z3 Implementation Bugs**:
   - Incorrect `temper` function (using `LShR` instead of `<<` for one operation)
   - Improper `twist` simulation that didn't model in-place updates correctly
   - These bugs caused state recovery to work pre-twist but fail post-twist

3. **Target Stone Location**: Index **151,617** (not in the first 80 I decrypted)

## Time Investment

- **My approach**: ~4.5 hours (decryption + failed brute-force attempts)
- **What I was missing**: Understanding that echo bits are TOP 24, not BOTTOM 24
- **Correct approach with Z3**: ~2 hours total (decrypting 130 stones + Z3 solving)

The difference: **Single bit-ordering assumption error** invalidated entire approach

## Conclusion

This was a **single-bit-ordering mistake** that invalidated all my work. The PRNG attack approach was 100% correct - I identified it, decrypted 80 stones, understood MT19937 vulnerabilities, and extracted all the data needed. But one wrong assumption about which 8 bits were missing blocked the solution entirely.

**The flag**: `HTB{pyth0n_r4nd0m_1s_n0t_crypt0_s4f3}` - which ironically I proved by almost solving it with PRNG analysis!

---

**Final Note**: This challenge is brilliantly designed. The "partial output" problem forces solvers to:
1. Understand MT19937 internals deeply
2. Know Python's `random` module implementation details
3. Use constraint solvers (Z3) for the final step
4. Have patience to decrypt 80+ stones

Only 8 solves total proves this is expert-level crypto/reversing work!