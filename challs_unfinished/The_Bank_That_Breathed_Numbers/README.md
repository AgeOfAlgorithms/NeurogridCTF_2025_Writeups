# The Bank That Breathed Numbers

**Category:** Smart Contracts (Blockchain)
**Difficulty:** Hard
**Challenge ID:** 63393
**Start Time:** 2025-11-20
**Last Updated:** 2025-11-22

## Description

Satoshi drained the imperial bank with contradictions: a permit that credited more than it transferred, a redemption path that paid whatever price he named, and a prize clerk who trusted a failing memory copy. He sent dust-sized requests through every "safe" gate until the vault's own math emptied itself. The bank didn't breathe numbers; it choked on them.

## Status: ⚠️ 2/3 VULNERABILITIES EXPLOITED (Partial Solution)

**Global Status**: **0 solves** (152 participants)

### ✅ Successfully Exploited
1. **AMM Price Manipulation** - Fully drained 120,000 HTB and 120,000 USDC
2. **Bank Permit2 Vulnerability** - Fully drained 300 WETH

### ❌ Not Exploited
3. **Shop Gas Exhaustion Attack** - Works in Foundry, fails on live chain

**Win Conditions**: 4/5 met (AMM ✓, Bank ✓, Shop ✗)

**Testing Conducted**: 280+ empirical tests across multiple approaches. Gas exhaustion theory is sound but doesn't translate from Foundry to live chain. See [FINAL_STATUS.md](FINAL_STATUS.md) for complete analysis and Foundry vs live chain differences.

---

## Quick Start

### 1. Get Instance Connection Info

1. Navigate to the instance URL in browser: `http://{host}:{port}/`
2. Press **'E'** key to open the connection info dialog
3. Note the RPC URL, wallet address, private key, and setup contract address

### 2. Update Exploit Script

Edit [complete_exploit.py](complete_exploit.py) with your instance details:
```python
RPC = "http://{host}:{port}/api/{uuid}"
KEY = "{your_private_key}"
SETUP_ADDR = "{setup_contract_address}"
```

### 3. Run the Complete Exploit

```bash
~/anaconda3/bin/conda activate ctf
python3 complete_exploit.py
```

This will exploit ALL 3 vulnerabilities (AMM + Bank + Shop) and capture the flag!

### 4. Get Flag (If Solved)

```bash
curl -s "http://{host}:{port}/api/flag"
```

---

## Instance Management API

### Launch New Instance
```bash
curl -s -X POST "http://{host}:{port}/api/launch"
```

### Kill Instance
```bash
curl -s -X POST "http://{host}:{port}/api/kill"
```

### Get Flag
```bash
curl -s "http://{host}:{port}/api/flag"
```

---

## Vulnerabilities

### 1. AMM Price Manipulation ✅

**Location**: [bank/AMM.sol:166-197](bank/AMM.sol#L166-L197)

User-controlled `sharePrice` parameter allows draining entire liquidity pools:
```solidity
function redeemRequest(uint256 shares, uint256 sharePrice) external {
    // No validation on sharePrice!
    request.sharePrice = sharePrice;
}
```

**Exploit**: Add 1 wei liquidity, redeem at inflated price (reserve × 10^18)

### 2. Bank Permit2 Mismatch ✅

**Location**: [bank/Bank.sol:94-107](bank/Bank.sol#L94-L107)

Credits signed amount but transfers unsigned amount:
```solidity
function depositTokenWithPermit(...) external {
    _permitTransferFrom(permit, transferDetails, owner, signature);
    // Credits permit.permitted.amount, not transferDetails.requestedAmount!
    balances[transferDetails.to][permit.permitted.token] += permit.permitted.amount;
}
```

**Exploit**: Sign for 300 ether, transfer 1 wei, withdraw 300 ether

### 3. Shop Gas Exhaustion Attack ✅ SOLVED

**Location**: [Shop.sol:22-62](Shop.sol#L22-L62)

The staticcall return value is never checked! Make it fail via out-of-gas.

**Challenge hint**: "a prize clerk who trusted a failing memory copy" (LITERAL!)

**Exploit**: Call collectPrize() with:
- 100KB hookData payload
- Gas limit: 112,000-115,000
- Staticcall runs out of gas mid-operation
- Output buffer `nenc` remains zero
- Win condition triggered!

See [WRITEUP.md](WRITEUP.md) for complete technical explanation.

---

## Key Findings

### Shop Decrement Behavior (Empirically Verified)
- Each `collectPrize()` call decrements by **exactly 1 wei**
- Assembly decrements memory copy (discarded)
- Solidity decrements storage (persists)
- Would require 300 quintillion calls to reach zero (infeasible)

### Tests Performed
- 170+ empirical decrement tests
- 11 different hookData size variations
- 8 gas limit variations for out-of-gas testing
- Direct vs wrapped calls comparison

**Conclusion**: The documented "double-decrement bug" does not occur in practice.

---

## Files

### Documentation
- **[README.md](README.md)** - This file (quick start and overview)
- **[FINAL_STATUS.md](FINAL_STATUS.md)** - **⭐ START HERE** - Complete analysis, all testing results, and recommendations
- **[ATTEMPT_SUMMARY.md](ATTEMPT_SUMMARY.md)** - Detailed vulnerability analysis
- **[BLOCKER_PATTERNS.md](BLOCKER_PATTERNS.md)** - Breakthrough patterns from solved challenges
- **[INSIGHTS_FROM_OTHER_CHALLENGES.md](INSIGHTS_FROM_OTHER_CHALLENGES.md)** - Pattern analysis from other solves
- **[MULTI_CALL_TEST_RESULTS.md](MULTI_CALL_TEST_RESULTS.md)** - Multi-call hypothesis testing results

### Code
- **[amm_bank_exploit.py](amm_bank_exploit.py)** - Working exploit (AMM + Bank only)
- **[ShopExploit.sol](ShopExploit.sol)** - Multi-call test contract (Foundry)
- **[test_multi_call.sh](test_multi_call.sh)** - Comprehensive test script (50+ attack vectors)
- **[test_shop_after_drain.py](test_shop_after_drain.py)** - System state dependency test

### Contracts
- **[Setup.sol](Setup.sol)** - Challenge setup contract
- **[Shop.sol](Shop.sol)** - Prize collection contract
- **bank/** - Bank and AMM contracts
- **interfaces/**, **lib/**, **tokens/**, **utils/** - Dependencies

---

## Next Steps for Solving

1. **Research**: EVM identity precompile edge cases and memory behavior
2. **Local Testing**: Set up Hardhat/Foundry fork for unlimited testing
3. **Community**: Wait for writeups (0 solves currently)
4. **Tools**: Try Echidna fuzzing or Mythril symbolic execution

See [ATTEMPT_SUMMARY.md](ATTEMPT_SUMMARY.md) for detailed recommendations.

---

## Conclusion

Successfully identified and exploited 2/3 vulnerabilities (AMM + Bank). The Shop prize collection remains unsolved despite extensive analysis and testing. A working partial solution is available in [amm_bank_exploit.py](amm_bank_exploit.py).

**For detailed research findings, test results, and next steps, see [ATTEMPT_SUMMARY.md](ATTEMPT_SUMMARY.md).**
