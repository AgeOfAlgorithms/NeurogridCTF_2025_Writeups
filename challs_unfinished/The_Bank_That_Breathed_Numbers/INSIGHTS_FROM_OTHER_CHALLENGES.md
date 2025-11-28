# Insights from Solved Challenges

**Analysis Date**: 2025-11-22
**Purpose**: Extract patterns from solved challenges to help solve Shop vulnerability

---

## Challenge 1: The Debt That Hunts the Poor

### Key Breakthrough Patterns

1. **Hidden Mechanic Discovery** ⭐
   - **Pattern**: Seized collateral goes to liquidator's wallet (not destroyed!)
   - **Lesson**: State changes don't always go where you expect
   - **For Shop**: Maybe staticcall output goes somewhere unexpected?

2. **Self-Interaction Loop** ⭐⭐
   - **Pattern**: Self-liquidation reset the YLD claim flag
   - **Mechanism**: Contract called itself through liquidation mechanism
   - **For Shop**: Could we call Shop through another contract path that changes behavior?

3. **Precise Cycle Planning**
   - **Pattern**: Needed exactly 7 cycles (6 deposits + 1 keep)
   - **Lesson**: Sometimes you need a specific number of operations
   - **For Shop**: Maybe multiple collectPrize() calls in specific pattern?

4. **State Persistence Trick**
   - **Pattern**: Re-depositing seized collateral maintained VIP status
   - **Lesson**: You can manipulate state by returning things to where they came from
   - **For Shop**: Could we manipulate memory and return it to reset state?

5. **Catch-22 Avoidance**
   - **Pattern**: Couldn't withdraw YLD after depositing, so kept last claim in wallet
   - **Lesson**: Sometimes you need to avoid the "normal" path entirely
   - **For Shop**: Maybe we shouldn't call collectPrize() through Setup?

---

## Challenge 2: The Contribution That Undid The Harbor

### Key Breakthrough Patterns

1. **Same-Block Requirement** ⭐⭐⭐
   - **Pattern**: Proposals expired after block, needed batching in single transaction
   - **Mechanism**: Helper contract to batch propose() + accept() atomically
   - **For Shop**: Maybe collectPrize() needs to be called multiple times in SAME transaction?

2. **EOA vs Contract Tricks** ⭐⭐
   - **Pattern**: EIP-7702 allows EOA to have code while maintaining EOA identity
   - **Lesson**: The boundary between EOA and contract can be blurred
   - **For Shop**: Maybe we need to call from a specific type of caller?

3. **Receive Function Critical** ⭐
   - **Pattern**: Delegated contract needed receive() to accept ETH
   - **Lesson**: Execution context matters for transfers
   - **For Shop**: Maybe the staticcall behaves differently based on caller's code?

4. **Status Codes Misleading**
   - **Pattern**: Transaction showed failed (status: 0) but delegation actually worked
   - **Lesson**: Always verify state changes independently of tx status
   - **For Shop**: Maybe our tests were wrong about what's actually happening?

5. **Tool Selection**
   - **Pattern**: Foundry worked where web3.py didn't for EIP-7702
   - **Lesson**: Different tools expose different capabilities
   - **For Shop**: Maybe we need to use Foundry instead of web3.py?

---

## Application to "The Bank That Breathed Numbers" Shop Vulnerability

### Challenge Description Clue
> "a prize clerk who trusted a **failing memory copy**"

### Current Understanding
- Staticcall to identity precompile (address 4) copies memory
- Reading at offset 0x54 needs to return 0
- Empirical tests show 1 wei decrement per call
- Out-of-gas doesn't help (either succeeds or reverts)

---

## New Hypotheses Based on Writeup Patterns

### Hypothesis 1: Multiple Calls in Same Transaction ⭐⭐⭐
**Inspired by**: Contribution's same-block batching

**Theory**: The Shop vulnerability might require calling collectPrize() multiple times in the SAME transaction. Memory state could accumulate or interfere across calls.

**Test Approach**:
```solidity
contract ShopExploit {
    function multiCall(address setup, bytes calldata hookData) external {
        ISetup(setup).collectPrize(hookData);
        ISetup(setup).collectPrize(hookData);
        ISetup(setup).collectPrize(hookData);
        // ... more calls in same transaction
    }
}
```

**Why This Might Work**:
- Free memory pointer (0x40) advances with each call
- Multiple staticcalls in same transaction might leave memory in unexpected state
- The "failing memory copy" could mean later calls read from wrong memory location

---

### Hypothesis 2: Self-Interaction Through Different Path ⭐⭐
**Inspired by**: Debt's self-liquidation loop

**Theory**: Call Shop.collectPrize() directly from a contract that also calls it through Setup, creating interference.

**Test Approach**:
```solidity
contract ShopExploit {
    function exploit(address setup, address shop) external {
        IShop(shop).collectPrize("");  // Direct call
        ISetup(setup).collectPrize(""); // Through Setup
        // Does this create memory interference?
    }
}
```

---

### Hypothesis 3: Staticcall Interference via Reentrancy ⭐
**Inspired by**: Debt's liquidation reset mechanism

**Theory**: The identity precompile (address 4) is just a memory copy. What if we call collectPrize() while INSIDE a staticcall context?

**Test Approach**:
```solidity
contract ShopExploit {
    function exploit(address setup) external {
        // Try calling from within a staticcall context
        this.reentrantCall(setup);
    }

    function reentrantCall(address setup) external view {
        // This executes in staticcall context
        // What happens if we trigger another collectPrize() here?
    }
}
```

---

### Hypothesis 4: Memory Pointer Manipulation ⭐⭐
**Inspired by**: Contribution's execution context tricks

**Theory**: Manipulate the free memory pointer (0x40) before calling collectPrize() so the staticcall reads/writes to wrong locations.

**Test Approach**:
```solidity
contract ShopExploit {
    function exploit(address setup) external {
        assembly {
            // Save original free memory pointer
            let orig := mload(0x40)

            // Set free memory pointer to unusual value
            mstore(0x40, 0x1000)  // Or some other strategic value

            // Now call collectPrize - does staticcall read wrong memory?
        }
        ISetup(setup).collectPrize("");
    }
}
```

---

### Hypothesis 5: HookData as Memory Overlap ⭐⭐
**Inspired by**: Debt's precise cycle planning (exactly 7 cycles needed)

**Theory**: Craft hookData with specific length/content that causes the encoded data to align such that offset 0x54 reads zeros.

**Memory Layout Reminder**:
```
After staticcall, nenc contains:
Bytes 0-31:   dl (length value)
Bytes 32-63:  Prize ID
Bytes 64-95:  Prize amount (300 ether)
Bytes 96-127: hookData.length
Bytes 128+:   hookData

Reading at nenc + 0x54 (84 bytes):
Spans bytes 84-115 (32 bytes)
= Last 12 bytes of prize amount + First 20 bytes of hookData.length
```

**Current Prize Amount**: 300 ether = 0x01043561a8829300000 (has non-zero bytes)

**New Insight**: What if we need the prize to be decremented to a specific value first?

**Test Approach**:
- Calculate: What prize value would have zeros at bytes 84-95?
- Prize is 64 bytes (ID + amount), so bytes 84-95 are bytes 52-63 of encodedPrize
- That's bytes 20-31 of the amount value
- For a 32-byte amount, bytes 20-31 being zero means: 0x0000000000000000000000XXXXXXXXXXXX
- Maximum value with zeros at those bytes: 0x0000000000000000000000FFFFFFFFFFFF = ~281 trillion wei = 0.000281 ether

**Implication**: We need to decrement the prize from 300 ether to ~0.000281 ether???
- That's 300 - 0.000281 = 299.999719 ether to decrement
- At 1 wei per call, that's 300 quintillion calls - IMPOSSIBLE

**But wait**: What if hookData.length can be manipulated to have zeros in the right place?

---

### Hypothesis 6: Large HookData Creates Memory Expansion ⭐
**Inspired by**: Contribution's gas mechanics

**Theory**: Very large hookData causes memory expansion, affecting where staticcall writes or how it behaves.

**Test Approach**:
```python
# Try extremely large hookData
huge_data = b'A' * 100000  # 100KB
setup.functions.collectPrize(huge_data).call()
```

---

## Recommended Next Steps (Priority Order)

### Priority 1: Multiple Calls in Same Transaction ⭐⭐⭐
This is the STRONGEST lead based on the Contribution challenge's same-block requirement pattern.

**Action**:
1. Create Solidity helper contract with multi-call function
2. Deploy using Foundry
3. Call collectPrize() 2-10 times in single transaction
4. Check if collected becomes True

### Priority 2: Foundry Instead of Web3.py
Both writeups emphasized tool selection matters.

**Action**:
1. Port testing to Foundry framework
2. Use `cast` and `forge` instead of Python
3. May expose different behavior or capabilities

### Priority 3: Memory Pointer Manipulation
**Action**:
1. Create contract that manipulates memory before calling
2. Test different memory pointer values
3. Check if affects staticcall behavior

### Priority 4: Direct Shop Calls (Already Tested)
**Status**: Already tested in previous sessions, but try WITH contract caller

---

## Key Insights Summary

1. ✅ **Same-transaction batching** is a major pattern in blockchain exploits
2. ✅ **Tool selection matters** - Foundry may work where web3.py doesn't
3. ✅ **Hidden mechanics exist** - state goes to unexpected places
4. ✅ **Self-interaction** through different paths can create exploits
5. ✅ **Memory/execution context** matters more than we initially thought

The most promising lead is **Hypothesis 1: Multiple calls in same transaction**. This aligns with:
- The "failing memory copy" clue (memory state accumulates)
- The Contribution challenge's same-block pattern
- The fact that we haven't tested this approach yet

---

## Files to Create

1. `ShopExploit.sol` - Helper contract for multi-call testing
2. `test_multi_call.sh` - Foundry script to deploy and test
3. `MULTI_CALL_RESULTS.md` - Document test results

This approach is significantly different from our previous testing and has strong support from solved challenge patterns.
