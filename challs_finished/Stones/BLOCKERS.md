# Blockers & Progress

## Current Status
**Date:** 2025-11-21
**Status:** IN PROGRESS (Solving)

## Solved Blockers

### 1. Missing Echo Bits (PRNG State Recovery)
**Issue:** `random.getrandbits(24)` consumes 32 bits but only returns 24. The missing 8 bits prevented standard predictors from working.
**Resolution:** Used Z3 SMT solver to handle partial constraints.
**Outcome:** Successfully recovered a state that predicts the first 80 stones perfectly.

### 2. State Divergence (Insufficient Constraints)
**Issue:** The recovered state correctly predicts the first ~700 outputs but diverges afterwards.
**Cause:** The missing 8 bits in the echo outputs (indices 8, 17, 26...) create "holes" in the state. These holes are not fully constrained by the available 720 outputs because the twist operation (at index 624) propagates these uncertainties to the future state. We need more outputs *after* the twist to constrain the pre-twist missing bits.
**Resolution:** Decrypting more stones (indices 80-160) to provide ~1440 total outputs. This should be sufficient to constrain the state fully (need > 1250 outputs).
**Action:** Running `parallel_decrypt.py` to decrypt 80 more stones.

## Next Steps
1. Wait for `parallel_decrypt.py` to finish.
2. Merge data.
3. Run `solve_stones_z3.py` with the larger dataset.
4. Predict the target stone index.
5. Decrypt the flag.
