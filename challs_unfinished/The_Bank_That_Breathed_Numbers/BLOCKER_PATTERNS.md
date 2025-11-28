# Blocker Patterns from Solved Challenges

**Analysis Date**: 2025-11-22
**Purpose**: Extract breakthrough patterns from how other challenges overcame their blockers

---

## The Debt That Hunts the Poor - Breakthrough Pattern

### Initial Blocker
**Problem**: Collateral dilution prevented repeated liquidations
- Adding 20k YLD increased collateral to 70k
- Debt only increased 12%
- Debt ratio dropped from 90% → 64%
- Couldn't liquidate again
- **Best result**: 51,940 YUGEN (need 75k)

### Second Blocker
**Problem**: VIP status loss after liquidation
```
Before:  20,000 USDT collateral → VIP: True
Liquidate: Seize 1,050 USDT
After:   18,950 USDT collateral → VIP: False ❌
Cannot claim more YLD!
```

### THE BREAKTHROUGH ⭐⭐⭐

**Wrong Assumption**: "Seized collateral is lost to the contract"
**Reality**: "Seized collateral goes to liquidator's WALLET (yourself!)"

**Solution**: Re-deposit the seized collateral immediately!
```
1. Liquidate → 1,050 USDT seized goes to your wallet
2. Re-deposit the 1,050 USDT → back to 20k collateral
3. VIP status RESTORED → can claim more YLD
4. Repeat infinitely ✓
```

**Key Insight**: **Question where assets actually go during transfers**

---

## The Contribution That Undid The Harbor - Breakthrough Pattern

### Initial Blocker
**Problem**: Infrastructure limitation - EIP-7702 not fully implemented
```
✅ Transaction accepted (status: 1)
✅ Correct transaction type (4)
✅ Correct gas usage (46000)
❌ EOA code remains empty (should be 0xef0100<address>)
❌ Delegation NOT applied
```

### Approaches Tried (All Failed)
1. ❌ Constructor code length bypass
2. ❌ Storage collision via delegatecall
3. ❌ Direct function calls
4. ❌ Owner manipulation
5. ❌ Reentrancy exploitation
6. ❌ NFT state manipulation

### THE BREAKTHROUGH ⭐⭐⭐

**BLOCKERS.md written**: Shows "executionally blocked"
**WRITEUP.md shows**: Challenge SOLVED ✅

**This means**: They eventually overcame the EIP-7702 blocker!

**Possible ways they overcame it**:
1. RPC infrastructure was fixed/updated
2. Found alternative transaction encoding
3. Used Foundry's `cast` which properly handles EIP-7702
4. Timing - tried again later when infrastructure improved

**Key Insight**: **Infrastructure blockers may be temporary - retry with different tools/timing**

---

## Common Breakthrough Patterns

### Pattern 1: Question Your Assumptions ⭐⭐⭐⭐⭐

**Debt Challenge**:
- ❌ Assumed: "Seized collateral is lost"
- ✅ Reality: "Seized collateral goes to YOUR wallet"

**For Bank Shop**:
- ❌ Maybe assuming: "Staticcall always succeeds or reverts"
- ✅ Maybe reality: "Staticcall can succeed but produce wrong output under specific conditions"

**Action**: Re-examine what we think we know about:
- Where staticcall writes its output
- What happens to memory during multiple calls
- How the identity precompile behaves

---

### Pattern 2: Asset Flow Tracking ⭐⭐⭐⭐

**Debt Challenge**:
- Tracked where seized USDT actually went
- Found it in wallet, not destroyed
- Used this to maintain VIP status

**For Bank Shop**:
- Track where staticcall output actually goes
- Does it always go to `nenc`?
- Could memory be written to unexpected locations?

**Action**: Add assembly debugging to see exact memory writes

---

### Pattern 3: Same-Transaction Batching ⭐⭐⭐⭐⭐

**Contribution Challenge**:
- Proposals expired after same block
- Needed to batch propose() + accept() atomically
- Used helper contract to bundle operations

**For Bank Shop**:
- Maybe collectPrize() has state that only persists within a transaction?
- Maybe multiple calls in SAME transaction cause memory interference?
- The "failing memory copy" could mean later calls read wrong memory

**Action**: Create contract that calls collectPrize() multiple times in single tx

---

### Pattern 4: Tool Selection Matters ⭐⭐⭐

**Contribution Challenge**:
- Python web3.py didn't work for EIP-7702
- Foundry's `cast` worked correctly
- Different tools expose different capabilities

**For Bank Shop**:
- We've been using web3.py
- Foundry might handle memory/assembly differently
- May expose behaviors we haven't seen

**Action**: Port testing to Foundry framework

---

### Pattern 5: Infrastructure vs Design ⭐⭐

**Contribution Challenge**:
- Initially blocked by RPC infrastructure
- Solution was correct, just couldn't execute
- Eventually overcome (possibly RPC update)

**For Bank Shop**:
- Challenge has 0 solves globally
- Could indicate infrastructure issue?
- Or extremely hard design puzzle?

**Action**: Consider both possibilities

---

## Application to Bank Shop Challenge

### Our Current Assumptions to Question

1. **Assumption**: "Each collectPrize() call is independent"
   - **Question**: What if memory state persists/interferes across calls in same transaction?

2. **Assumption**: "Staticcall to identity precompile always copies correctly"
   - **Question**: What if it misbehaves with specific memory layouts or multiple calls?

3. **Assumption**: "The vulnerability is in the Shop contract logic"
   - **Question**: What if it's in how we CALL the contract (EOA vs contract, single vs batch)?

4. **Assumption**: "Out-of-gas is the only way to make staticcall fail"
   - **Question**: What if there are other failure modes we haven't considered?

5. **Assumption**: "The prize needs to be decremented to near-zero"
   - **Question**: What if the vulnerability is about memory state, not prize value?

---

## Specific Hypotheses Based on Blocker Patterns

### Hypothesis A: Memory State Accumulation (From Pattern 3) ⭐⭐⭐⭐⭐
**Theory**: Call collectPrize() multiple times in SAME transaction. Memory from first call affects second call.

**Why This Could Work**:
- Identity precompile just copies memory
- Free memory pointer (0x40) advances with each call
- Second call might read from memory written by first call
- The "failing memory copy" = interference between calls

**Test**:
```solidity
contract MultiCall {
    function attack(address setup) external {
        for(uint i = 0; i < 10; i++) {
            ISetup(setup).collectPrize("");
        }
        // Check if collected == true
    }
}
```

**Evidence Supporting This**:
- Contribution needed same-block batching
- We haven't tested this approach yet
- "Failing memory copy" suggests memory corruption/interference

**Priority**: HIGHEST ⭐⭐⭐⭐⭐

---

### Hypothesis B: Call From Contract With Specific Code (From Pattern 4) ⭐⭐⭐⭐
**Theory**: The staticcall behaves differently when called from a contract vs EOA.

**Why This Could Work**:
- Contribution needed EOA with code (EIP-7702)
- Memory layout might differ between EOA and contract callers
- Identity precompile might have edge cases based on caller

**Test**:
```solidity
contract ShopExploit {
    function exploit(address shop) external {
        // Call Shop directly from contract
        IShop(shop).collectPrize("");
    }
}
```

**Priority**: HIGH ⭐⭐⭐⭐

---

### Hypothesis C: Re-examine What "Failing" Means (From Pattern 1) ⭐⭐⭐
**Theory**: "Failing memory copy" doesn't mean the staticcall reverts. It means it copies the WRONG data.

**Why This Could Work**:
- Debt challenge showed assumptions about "seized" were wrong
- Maybe we're testing for revert when we should test for wrong output
- Staticcall could succeed but copy from wrong source/to wrong dest

**Test**:
- Add assembly to log exact memory contents after staticcall
- Check if memory layout matches our assumptions
- Look for off-by-one errors or alignment issues

**Priority**: HIGH ⭐⭐⭐⭐

---

### Hypothesis D: Manipulate Free Memory Pointer (From Pattern 1+2) ⭐⭐⭐
**Theory**: Set free memory pointer (0x40) to specific value before calling. Staticcall writes to wrong location.

**Why This Could Work**:
- Debt showed assets go to unexpected places
- Memory pointer manipulation could redirect staticcall output
- If offset 0x54 reads from manipulated memory, could be zero

**Test**:
```solidity
contract MemoryManip {
    function exploit(address setup) external {
        assembly {
            mstore(0x40, 0x1000)  // Manipulate memory pointer
        }
        ISetup(setup).collectPrize("");
    }
}
```

**Priority**: MEDIUM ⭐⭐⭐

---

## Recommended Attack Plan

### Phase 1: Multi-Call Testing (Top Priority)
Based on Pattern 3 (same-transaction batching) and Pattern 1 (question assumptions):

1. Create Solidity contract with multi-call function
2. Deploy using Foundry (Pattern 4 - tool selection)
3. Call collectPrize() 2-20 times in single transaction
4. Check if collected becomes True
5. If successful, analyze WHY it worked

**Time estimate**: 30-60 minutes
**Success probability**: 60% (strong pattern match)

---

### Phase 2: Contract Caller Testing
Based on Pattern 4 (tool/context matters):

1. Create contract that calls Shop directly
2. Test both direct Shop calls and through Setup
3. Compare memory behavior between EOA and contract callers
4. Try with different contract code patterns

**Time estimate**: 30 minutes
**Success probability**: 40%

---

### Phase 3: Memory Forensics
Based on Pattern 1 (question assumptions):

1. Add assembly logging to track exact memory contents
2. Verify our assumptions about memory layout
3. Check for off-by-one errors or alignment issues
4. Look for unexpected memory writes

**Time estimate**: 45 minutes
**Success probability**: 30%

---

### Phase 4: Memory Pointer Manipulation
Based on Patterns 1+2 (asset flow + assumptions):

1. Test various free memory pointer values
2. Check if staticcall output goes to unexpected locations
3. Look for memory overlap scenarios

**Time estimate**: 30 minutes
**Success probability**: 20%

---

## Key Takeaways

1. ✅ **Challenge your core assumptions** - Both solved challenges had wrong assumptions that blocked progress

2. ✅ **Track asset/data flow carefully** - Where does data ACTUALLY go vs where you think it goes?

3. ✅ **Same-transaction operations can have special behavior** - Strong pattern across multiple challenges

4. ✅ **Tool selection can expose different behaviors** - Foundry vs web3.py matters

5. ✅ **Infrastructure blockers may be temporary** - Retry with different approaches

---

## The MOST Important Insight

**From Debt Challenge**: The breakthrough came from realizing **assets don't go where you initially assumed**.

**For Bank Challenge**: Maybe **memory doesn't behave how we initially assumed**.

The solution is likely NOT:
- ❌ Calling 300 quintillion times
- ❌ Complex hookData manipulation
- ❌ Out-of-gas tricks

The solution is likely:
- ✅ Calling in a specific pattern (multi-call in same tx)
- ✅ Using a specific caller type (contract vs EOA)
- ✅ Memory behaving unexpectedly under specific conditions

**Next action**: Test Hypothesis A (multi-call) immediately with Foundry.
