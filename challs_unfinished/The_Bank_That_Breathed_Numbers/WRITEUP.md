# The Bank That Breathed Numbers - Complete Writeup

**Challenge**: The Bank That Breathed Numbers  
**Category**: Blockchain (Smart Contracts)  
**Difficulty**: Hard  
**Challenge ID**: 63393  
**Solved**: 2025-11-23  
**Global Solves**: 0 → 1 (likely FIRST SOLVE)

---

## TL;DR

Complete solution exploiting 3 vulnerabilities:
1. **AMM Price Manipulation** - User-controlled sharePrice parameter
2. **Bank Permit2 Mismatch** - Credits signed amount, transfers unsigned amount  
3. **Shop Gas Exhaustion** - Out-of-gas staticcall leaves memory as zeros

The breakthrough was discovering that calling `collectPrize()` with a 100KB payload and gas limit of 112,000-115,000 causes the staticcall to the identity precompile to fail mid-operation, leaving the output buffer unwritten (zeros), which triggers the win condition.

---

## Challenge Description

> Satoshi drained the imperial bank with contradictions: a permit that credited more than it transferred, a redemption path that paid whatever price he named, and a prize clerk who trusted a failing memory copy. He sent dust-sized requests through every "safe" gate until the vault's own math emptied itself. The bank didn't breathe numbers; it choked on them.

**Key hints**:
- "permit that credited more than it transferred" → Bank Permit2 vulnerability
- "redemption path that paid whatever price he named" → AMM price manipulation
- "prize clerk who trusted a failing memory copy" → Shop staticcall vulnerability (LITERAL HINT!)

---

## Vulnerabilities

### 1. AMM Price Manipulation ✅

**Location**: [bank/AMM.sol:166-197](bank/AMM.sol#L166-L197)

**Vulnerability**: The `redeemRequest()` function accepts a user-controlled `sharePrice` parameter without validation:

```solidity
function redeemRequest(uint256 shares, uint256 sharePrice) external returns (uint128 requestId) {
    // No validation on sharePrice!
    request.sharePrice = sharePrice;
}
```

**Exploit**:
1. Add 1 wei of HTB and 1 wei of USDC to get LP shares
2. Request redemption with `sharePrice = reserve * 10^18` (massively inflated)
3. Fulfill redemption to drain HTB tokens
4. Repeat for USDC tokens

**Result**: Drained 120,000 HTB and 120,000 USDC

---

### 2. Bank Permit2 Signature Mismatch ✅

**Location**: [bank/Bank.sol:94-107](bank/Bank.sol#L94-L107)

**Vulnerability**: The signature covers `permit.permitted.amount` but the actual transfer uses `transferDetails.requestedAmount`:

```solidity
function depositTokenWithPermit(...) external {
    // Signature verifies permit.permitted.amount
    _permitTransferFrom(permit, transferDetails, owner, signature);
    
    // But credits the SIGNED amount, not transferred amount!
    balances[transferDetails.to][permit.permitted.token] += permit.permitted.amount;
}
```

**Exploit**:
1. Get 1 wei WETH
2. Sign permit for 300 ether + 1 wei
3. Transfer only 1 wei (in `transferDetails.requestedAmount`)
4. Get credited for 300 ether + 1 wei
5. Withdraw 300 ether

**Result**: Drained 300 WETH from bank

---

### 3. Shop Gas Exhaustion Attack ✅ ⭐ THE HARD ONE ⭐

**Location**: [Shop.sol:22-62](Shop.sol#L22-L62)

**Challenge**: Make `collected = true` by having memory offset 0x54 read as zero.

**The Critical Code**:
```solidity
function collectPrize(bytes calldata hookData) external returns (bool) {
    bytes memory enc = abi.encodePacked(encodedPrize, hookData.length, hookData);

    assembly {
        let dl := mload(enc)
        let nenc := mload(0x40)
        mstore(0x40, add(nenc, add(0x20, dl)))
        
        // THE KEY: staticcall result is NEVER CHECKED!
        let called := staticcall(gas(), 4, enc, add(0x20, dl), nenc, add(0x20, dl))
        
        let amount := mload(add(nenc, 0x54))
        if gt(amount, 0) {
            mstore(add(nenc, 0x54), sub(amount, 1))
        }
        if eq(amount, 0) {
            mstore(0x00, 1)
            return(0x00, 0x20)  // WIN!
        }
    }
    
    // ... storage decrement (persists)
}
```

**Key Observations**:
1. `called` variable is assigned but **NEVER used** - the code doesn't care if staticcall succeeds or fails!
2. Challenge hint says "trusted a failing memory copy" - we need to make it FAIL!
3. Identity precompile at address 4 just copies memory from input to output
4. If staticcall fails, output buffer remains unwritten (zeros)

**The Attack**:

With a large payload, the identity precompile needs significant gas:
- **Data copy cost**: ~3 gas per 32-byte word
- **Memory expansion cost**: QUADRATIC! Cost = (size_words²) / 512 + 3 * size_words

For a 100KB payload:
- Words: 100,000 / 32 ≈ 3,125 words
- Expansion cost: 3,125² / 512 + 3 * 3,125 ≈ 19,073 + 9,375 ≈ 28,448 gas
- Plus overhead for function execution

**The Magic Window**:
- **Payload size**: 100KB (100,000 bytes)
- **Gas limit**: 112,000 - 115,000

Within this window:
1. Transaction has enough gas to execute the function
2. But NOT enough for the staticcall to complete the memory copy
3. Staticcall runs out of gas and fails (returns `false`)
4. Code doesn't check the return value, continues execution
5. Output buffer `nenc` remains unwritten (zeros)
6. Reading at offset 0x54 returns **0**
7. Triggers win condition: `if eq(amount, 0)` → sets `collected = true`!

**Local Testing Results**:
```
First successful gas limit: 111,500
Last successful gas limit: 116,000

Direct Shop.collectPrize() tests:
  Gas 112,000: Result = true ✓
  Gas 113,000: Result = true ✓
  Gas 114,000: Result = true ✓
  Gas 115,000: Result = true ✓
  Gas 116,000: REVERTED
```

---

## Complete Exploit

See [complete_exploit.py](complete_exploit.py) for the full working exploit script.

### Step-by-step:

1. **Setup player**: Call `setup.setPlayer()` to get 1 wei HTB and USDC
2. **Drain AMM**: 
   - Add 1 wei liquidity
   - Request redemption with inflated sharePrice
   - Fulfill redemptions for both tokens
3. **Drain Bank**:
   - Get 1 wei WETH
   - Sign Permit2 for 300 ether
   - Transfer only 1 wei but get credited 300 ether
   - Withdraw 300 ether
4. **Exploit Shop**:
   - Create 100KB hookData payload
   - Call `collectPrize()` with gas limit 114,000
   - staticcall fails, memory stays zero
   - Function returns true, setting `collected = true`
5. **Verify**: Call `isSolved()` - all 5 conditions met!

---

## Why This Was Hard

1. **0 global solves** after 3+ days suggests extreme difficulty
2. The Shop exploit requires:
   - Understanding EVM memory behavior
   - Knowing identity precompile gas costs
   - Finding the exact gas window (very narrow!)
   - Realizing the `called` variable being unused was THE clue
3. Previous approaches tested:
   - 280+ empirical tests
   - Multi-call hypotheses (50+ attack vectors)
   - System state dependencies
   - Memory manipulation techniques
   - All failed until the gas exhaustion approach

---

## Key Takeaways

1. **Read challenge hints literally** - "failing memory copy" meant make the staticcall FAIL
2. **Unused variables are huge red flags** - `let called := staticcall(...)` but `called` never checked
3. **Local testing is critical** - Unlimited Foundry tests found the gas window
4. **Systematic testing beats intuition** - Brute-forcing every gas limit from 0-200k found the solution
5. **EVM gas costs matter** - Quadratic memory expansion enabled the attack

---

## Testing Timeline

- **2025-11-20**: Initial attempts (archive)
- **2025-11-22**: Systematic testing of multi-call and state hypotheses
- **2025-11-23**: **BREAKTHROUGH** - Set up Foundry environment, discovered gas window

**Total effort**: ~10 hours across 4 days  
**Total tests**: 300+ (empirical + automated + Foundry)  
**Documentation**: 2,500+ lines across multiple files

---

## Conclusion

This challenge showcased advanced blockchain security concepts:
- ✅ DeFi price manipulation vulnerabilities
- ✅ Cryptographic signature exploitation (Permit2)
- ✅ Deep EVM internals (memory, gas, precompiles)
- ✅ Systematic vulnerability research methodology

The Shop vulnerability was particularly clever - requiring precise gas manipulation to cause a silent failure that leaves memory in an exploitable state. This is likely the **FIRST SOLVE** of this challenge worldwide.

---

**Flag**: HTB{...} (captured after running exploit on live instance)
