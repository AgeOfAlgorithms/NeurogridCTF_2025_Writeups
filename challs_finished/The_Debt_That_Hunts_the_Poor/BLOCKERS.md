# BLOCKERS - The Debt That Hunts the Poor

**Date**: 2025-11-22
**Status**: KEY INSIGHT DISCOVERED - Solution Path Identified
**Challenge ID**: 63357
**Solves**: 9/149 teams (increased from 1!)

## Summary

Successfully identified the CORE blocker that prevented previous attempts and discovered the solution approach.

## Previous Blocker (from archive attempts)

**Issue**: Collateral Dilution Problem
- Depositing 20k YLD increases collateral from 50k to 70k
- Debt only increases ~12% through accrual
- Debt ratio drops from 90% to 64% - can't liquidate again
- Best attempt: 51,940 YUGEN (need 75k)

## This Attempt - New Blocker Discovered

**Issue**: VIP Status Loss After Liquidation
**When**: After self-liquidation cycles
**What Happened**:
1. Started with 20k USDT collateral → VIP status
2. Added YLD collateral, borrowed YUGEN
3. Accrued debt to become liquidatable
4. Liquidated: repaid YUGEN, seized USDT collateral
5. **PROBLEM**: Seized 1,050 USDT from collateral → dropped to 18,950 USDT → LOST VIP
6. Cannot claim more YLD without VIP status!

**Evidence**:
```
Before liquidation:  Coll: 20000U, VIP: True
Liquidate: repay 1k YUGEN, seize 1.05k USDT
After liquidation:   Coll: 18950U, VIP: False  ← BLOCKED!
Claim YLD #2: FAILED - "not VIP"
```

## KEY INSIGHT DISCOVERED ✓

**Solution**: **Re-deposit seized collateral immediately after liquidation!**

**How it works**:
1. When you liquidate yourself, seized collateral goes to YOUR WALLET (not lost!)
2. Example: Seize 1,050 USDT → it appears in wallet balance
3. **Immediately re-deposit it** → collateral back to 20k → VIP regained!
4. Then claim YLD → unlimited cycles possible

**Complete Flow**:
```
1. Deposit 20k USDT → VIP
2. Claim & deposit YLD → increase borrowing capacity
3. Borrow YUGEN
4. Accrue debt → liquidatable
5. Liquidate: repay YUGEN, seize USDT (goes to wallet)
6. **RE-DEPOSIT seized USDT → VIP restored!**
7. Claim more YLD → repeat cycle
```

## Why This Works

- Seized collateral isn't destroyed - it goes to liquidator (yourself!)
- Re-depositing maintains the 20k USDT threshold for VIP
- Allows unlimited YLD claim cycles
- Each cycle adds YLD collateral → more borrowing capacity → more YUGEN

## Expected Result

With multiple cycles (est. 4-6 cycles):
- Accumulate 75k+ YUGEN through strategic borrowing
- Keep final 20k YLD in wallet
- Solve challenge ✓

## Previous Assumption That Was Wrong

❌ "After liquidation, collateral is lost and you can't maintain VIP"
✅ "Seized collateral goes to your wallet - re-deposit it!"

## Next Steps

1. Implement complete multi-cycle exploit
2. Re-deposit seized collateral after each liquidation
3. Track YLD carefully - keep final 20k in wallet
4. Execute and get flag

## Time Invested

- Archive attempts: ~4 hours
- This attempt: ~2 hours
- **Total**: ~6 hours

## Status

**Breakthrough achieved!** Solution path is clear. Need to implement full multi-cycle exploit with the re-deposit strategy.
