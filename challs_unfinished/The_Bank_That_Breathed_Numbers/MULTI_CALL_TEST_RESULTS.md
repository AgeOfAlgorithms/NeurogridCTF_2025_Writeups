# Multi-Call Test Results

**Date**: 2025-11-22
**Hypothesis**: Multiple collectPrize() calls in same transaction would cause memory interference
**Result**: ❌ DISPROVEN - All attacks failed
**Status**: This approach does NOT solve the challenge

---

## Hypothesis Background

Based on patterns from solved challenges:
- **The Contribution That Undid The Harbor**: Needed same-block batching for proposals
- **The Debt That Hunts the Poor**: Questioned assumptions about asset flow

**Theory**: Calling collectPrize() multiple times in single transaction would:
- Cause memory state accumulation
- Create interference between staticcalls
- Result in offset 0x54 reading zeros

---

## Tests Performed

### Attack 1: Multi-Call with Different Counts ❌
**Tested**: 2, 3, 5, 10, 20, 50 calls in same transaction
**Result**: All returned `collected = false`
**Conclusion**: Number of calls doesn't matter

### Attack 2: Multi-Call with Varying Data Sizes ❌
**Tested**: 0, 32, 64, 84, 128, 256 byte hookData
**Result**: All returned `collected = false`
**Conclusion**: hookData size doesn't affect multi-call behavior

### Attack 3: Alternating Call Patterns ❌
**Pattern**: Empty → 32 bytes → 64 bytes → 84 bytes → Empty
**Result**: `collected = false`
**Conclusion**: Specific patterns don't help

### Attack 4: Memory Pointer Manipulation ❌
**Approach**: Set free memory pointer to 0x1000, then 0x2000 before calls
**Result**: `collected = false`
**Conclusion**: Manipulating memory pointer doesn't redirect staticcall output

### Attack 5: Rapid Succession with Try/Catch ❌
**Approach**: Multiple calls with error handling
**Result**: `collected = false`
**Conclusion**: Error handling doesn't create special conditions

### Attack 6: Recursive Call Pattern ❌
**Tested**: Recursion depths 1, 2, 3, 5
**Result**: All returned `collected = false`
**Conclusion**: Call stack depth doesn't matter

---

## What This Rules Out

1. ❌ **Memory state accumulation** - Multiple calls don't interfere
2. ❌ **Free memory pointer manipulation** - Doesn't affect staticcall
3. ❌ **Call pattern dependency** - Patterns don't matter
4. ❌ **hookData size effects** - Size variations don't help
5. ❌ **Stack depth effects** - Recursion doesn't help
6. ❌ **Same-transaction batching** - This pattern doesn't apply here

---

## Implications

### The Vulnerability Is NOT About:
- Multiple calls creating interference
- Memory pointer redirection
- Call patterns or batching
- hookData manipulation
- Execution context depth

### The Vulnerability Likely IS About:
- Something specific to a SINGLE call's execution
- State of the contract/memory BEFORE the call
- How the staticcall is invoked (not HOW MANY times)
- A very specific condition we haven't discovered

---

## Challenge Analysis Revisited

### The Clue: "a prize clerk who trusted a failing memory copy"

**What we know**:
```solidity
bytes memory enc = abi.encodePacked(encodedPrize, hookData.length, hookData);

assembly {
    let dl := mload(enc)
    let nenc := mload(0x40)
    mstore(0x40, add(nenc, add(0x20, dl)))

    // This is the "memory copy" - staticcall to identity precompile
    let called := staticcall(gas(), 4, enc, add(0x20, dl), nenc, add(0x20, dl))

    // This is where it "trusts" the copy
    let amount := mload(add(nenc, 0x54))
    if eq(amount, 0) {
        // WIN CONDITION
        return(0x00, 0x20)
    }
}
```

**The staticcall**:
- `staticcall(gas(), 4, enc, add(0x20, dl), nenc, add(0x20, dl))`
- Copies from `enc` (but skips first 0x20 bytes - the length prefix)
- Copies `dl` bytes (the length value itself)
- Writes to `nenc`
- Returns success/failure in `called` (but this isn't checked!)

---

## New Observations

### Observation 1: The `called` Return Value Is Ignored
```solidity
let called := staticcall(...)
// called is assigned but NEVER USED!
// Code continues regardless of success/failure
```

**Implication**: The code doesn't care if staticcall succeeds or fails. It just reads from `nenc` afterward.

### Observation 2: The Copy Source Is Wrong
```solidity
staticcall(gas(), 4, enc, add(0x20, dl), nenc, add(0x20, dl))
                        ^^^
                        Copies FROM enc (includes length prefix!)
```

Should probably be:
```solidity
staticcall(gas(), 4, add(enc, 0x20), dl, nenc, dl)
                    ^^^^^^^^^^^^^^  ^^
                    Skip length,   Copy only data
```

**Current behavior**: Copies the length value PLUS data, which shifts everything

### Observation 3: Memory Layout After Staticcall
If staticcall copies FROM `enc` (not `enc + 0x20`):
```
enc memory:
[0-31]:   dl (length value)
[32-95]:  encodedPrize (64 bytes)
[96-127]: hookData.length
[128+]:   hookData

Staticcall copies FROM enc, TO nenc:
nenc[0-31]:   dl (copied from enc[0-31])
nenc[32-95]:  encodedPrize (copied from enc[32-95])
nenc[96-127]: hookData.length (copied from enc[96-127])
nenc[128+]:   hookData (copied from enc[128+])
```

This matches our previous analysis - the copy includes the length prefix.

---

## Remaining Hypotheses

### Hypothesis A: The Bug Is Intentional (Red Herring)
**Theory**: The staticcall copying from wrong offset is a red herring. The real vulnerability is elsewhere.

**Test**: Look for other vulnerabilities in Bank/AMM that affect Shop state

---

### Hypothesis B: Specific Contract State Required
**Theory**: Shop needs to be in a specific state (not just prize value) before collectPrize()

**Test**:
- Drain AMM and Bank FIRST
- Check if this affects Shop behavior
- Maybe the "failing" refers to the overall system state

---

### Hypothesis C: Direct Shop Call (Not Through Setup)
**Theory**: Calling Shop.collectPrize() directly instead of Setup.collectPrize()

**Test**: Already tested in previous sessions - didn't work

---

### Hypothesis D: Challenge Is Broken/Unsolvable
**Theory**: 0 solves globally suggests infrastructure or design issue

**Evidence**:
- 0 solves after 2+ days
- Multiple teams likely attempting
- Similar challenges had solves within hours

---

## Recommended Next Steps

1. **Test Hypothesis B**: Run AMM + Bank exploits, THEN test Shop
   - Maybe draining other contracts affects Shop's behavior
   - System-wide state might matter

2. **Deep Dive into SOLUTION.md Claims**
   - Re-read the "double-decrement" claim
   - Maybe there's a hidden truth we misunderstood

3. **Consider Infrastructure Issues**
   - Challenge might have a bug
   - Or RPC might not behave as expected (like Contribution's EIP-7702)

4. **Community Check**
   - Wait for first solve and writeup
   - 0 solves is unusual for a 2-day-old challenge

---

## Conclusion

The multi-call hypothesis was a reasonable approach based on strong patterns from solved challenges, but it has been systematically **disproven**. The Shop vulnerability is NOT about call batching, memory interference, or execution patterns.

The solution likely involves:
- A single, very specific condition
- Possibly related to overall system state
- Or an aspect of the staticcall we haven't considered yet

**Time invested in multi-call testing**: ~1 hour
**Value**: Eliminated a major hypothesis systematically
**Next**: Test system-wide state hypothesis (AMM + Bank → Shop)
