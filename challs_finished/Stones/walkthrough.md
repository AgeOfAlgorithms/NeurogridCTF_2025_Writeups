# Stones Challenge Walkthrough

## Challenge Overview
**Category:** Crypto
**Goal:** Decrypt the flag by recovering the PRNG state.
**Core Mechanism:** The challenge generates 2^20 "stones", each encrypted with a key derived from a 24-bit "echo" value. The echo value is the top 24 bits of a 32-bit MT19937 output. One stone contains a target "sigil_a" value. We need to find this stone, get its "sigil_b" (key), and decrypt the flag.

## Solution Strategy

### 1. PRNG State Recovery
The core difficulty was recovering the MT19937 state from partial outputs (24 bits out of 32).
- **Constraint:** `random.getrandbits(24)` returns the *top* 24 bits. The lower 8 bits are unknown.
- **Approach:** Use Z3 SMT solver.
    - Model the MT19937 state (624 32-bit integers).
    - Simulate the `twist` and `temper` operations symbolically.
    - Add constraints: `LShR(output, 8) == known_echo`.
    - For full 32-bit outputs (sigil_a/b parts), use `output == known_value`.

### 2. Data Collection
We needed enough outputs to constrain the state.
- **Initial Data:** 80 stones (indices 0-79) provided ~720 outputs.
- **Issue:** The "twist" operation (every 624 outputs) mixes the state. The missing 8 bits in the echo outputs created "holes" that propagated through the twist, causing state divergence after ~700 outputs.
- **Fix:** Decrypted more stones (indices 80-140) to provide ~1200 outputs. This fully constrained the state across the twist boundary.

### 3. Z3 Implementation Details
A critical bug was found in the initial Z3 script:
- **Bug 1:** The `temper` function used `LShR` (logical right shift) instead of `<<` (left shift) for one of the operations. This caused the solver to find a state that matched the pre-twist outputs but failed post-twist.
- **Bug 2:** The `twist` simulation needed to correctly model the in-place updates of the MT19937 state array.
- **Fix:** Corrected the `temper` function and implemented a batch `twist` function in Z3.

### 4. Execution
- Ran the solver with 130 stones.
- **Result:** SAT. State recovered.
- **Verification:** The recovered state correctly predicted the last stone (index 2^20 - 1).
- **Target Search:** Simulated the sequence to find the stone with the target `sigil_a`.
    - **Target Index:** 151617
    - **Target Sigil B:** `183220215873312840422958718294835564770`
- **Decryption:** Used `sigil_b` as the AES key to decrypt the flag.

## Flag
`HTB{pyth0n_r4nd0m_1s_n0t_crypt0_s4f3}`
