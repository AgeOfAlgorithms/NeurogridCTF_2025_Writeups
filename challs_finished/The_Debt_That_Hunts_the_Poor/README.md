# The Debt That Hunts the Poor

**Category**: Blockchain
**Difficulty**: Easy
**Points**: 950
**Challenge ID**: 63357
**Start Time**: 2025-11-22
**End Time**: 2025-11-22
**Status**: ✅ SOLVED

## Description

In Tamegawa, the new imperial lending hall promised "opportunity for all": anyone could borrow coin against their tools, boats, or harvest, but only "VIP liquidators" those who first locked twenty thousand coins in the system were allowed to seize collateral when a borrower slipped, and those VIPs kept a bonus cut of whatever they took; Satoshi sat quietly in the back and watched it happen, watched a fisherman lose his nets, watched a widow lose her rice field, watched a sick boy's medicine chest get "liquidated" because repayment was late by one sunset, and all of it went not to the hall, not to the village, but straight into the pockets of the already-rich who could afford VIP status; that night, Satoshi scratched the rule onto the lending house door in ash and oil "only the wealthy may harvest the desperate" and read it aloud in the square until people understood this wasn't a loan market, it was a feeding trough, and the borrowers were the feed.

## Solution Summary

**Win Condition**:
- 75,000 YUGEN tokens in wallet
- 20,000 YLD tokens in wallet

**Vulnerability**: Unlimited YLD claims via self-liquidation reset + VIP status maintenance through re-depositing seized collateral

**Key Insight**: Seized collateral in liquidation goes to the liquidator's wallet (yourself), not destroyed. By immediately re-depositing it, VIP status is maintained, allowing unlimited YLD claim cycles.

**Strategy**:
1. Initial deposit: 10k USDT + 10k YUGEN (maintain VIP status)
2. Run 6 cycles of: Claim YLD → Deposit → Borrow → Accrue → Liquidate → Re-deposit seized USDT
3. Cycle 7: Claim YLD but keep it in wallet (don't deposit)

**Result**: 83,239 YUGEN + 20,000 YLD → Challenge Solved ✓

**Flag**: `HTB{S3lf_Yi3ld_L1qu1d4t10n_And_V1p_Yug3n_T0k3n_L00p_1bd3ace2ada235555493df6074375bd5}`

## Files

- `GET_FLAG.py` - Final working exploit script
- `WRITEUP.md` - Detailed writeup with vulnerability analysis and exploitation steps
- `BLOCKERS.md` - Documentation of blockers discovered and overcome
- `ATTEMPT.md` - Attempt summary comparing with previous failed attempts
- `*.sol` - Original smart contract source files
