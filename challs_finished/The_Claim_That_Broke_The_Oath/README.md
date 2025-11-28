# The Claim That Broke The Oath

## Challenge Information
- **Name**: The Claim That Broke The Oath
- **Category**: Blockchain/Smart Contract (Category ID: 14)
- **Difficulty**: Very Easy
- **Points**: 1000
- **Solves**: 0
- **Start Time**: 2025-11-20 13:30:00 UTC

## Description
When famine struck the river wards, the imperial vault promised fairness through a "claim rite" where anyone could request aid as long as their losses were approved by an assessor's seal. The decree sounded righteous, combining math and mercy in one. But Satoshi, a quiet scribe from the docks, doubted the purity of its numbers. He spent nights studying the relief ledgers and the symbols that certified truth until he saw that the vault's arithmetic did not balance. It bent in favor of those who already had plenty.

At dawn, he walked into the square carrying his own seal, one that should not exist, and submitted his claim. What followed was not a theft but a reckoning. The vault's counting script faltered, the books split open, and the market floor filled with what it had hidden. The stewards called it heresy. The people called it proof.

By nightfall, the vault's oath of "pure balance" was shattered. In its broken sums, Satoshi left a message no emperor could ignore: "Even the fairest claim can be written false."

## Challenge Files
- `BonusVaultETH.sol` - Main vault contract with deposit/withdraw/claimBonus functions
- `IOracleU.sol` - Oracle interface that provides adjustment values
- `Setup.sol` - Setup contract that defines win condition

## Win Condition
Make `vault.credits(player) > vault.MAX_BONUS()` (i.e., credits > 100 ether)

## Analysis
The challenge involves a smart contract vulnerability related to type casting and overflow.

## Solution
**Status**: ✅ SOLVED

**Vulnerability**: Type casting overflow in `claimBonus()` function
- The function casts `uint256` to `uint128` for validation
- But uses the full `uint256` value for credits addition
- By returning `2^128 + 50 ether` from a malicious oracle:
  - Check sees: `uint128(value)` = `50 ether` ✓
  - Credits get: `2^128 + 50 ether` ✓

**Flag**: `HTB{L0wB1t5_P4ss3d_H1ghBit5_Expl0d3d_eb0419c430a0cd136eff0eea2c65c34f}`

See [WRITEUP.md](WRITEUP.md) for detailed analysis and exploitation steps.
