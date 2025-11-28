# The Claim That Broke The Oath - Writeup

**Challenge**: The Claim That Broke The Oath
**Category**: Blockchain/Smart Contract
**Difficulty**: Very Easy
**Points**: 1000
**Flag**: `HTB{L0wB1t5_P4ss3d_H1ghBit5_Expl0d3d_eb0419c430a0cd136eff0eea2c65c34f}`

## Overview

This challenge exploits a type casting vulnerability in a Solidity smart contract where a `uint256` value is cast to `uint128` for validation but the full `uint256` value is used in the actual operation.

## Vulnerability Analysis

### The Vulnerable Code

The vulnerability exists in the `claimBonus` function in [BonusVaultETH.sol](BonusVaultETH.sol#L19-L25):

```solidity
function claimBonus(IOracleU oracle) external {
    uint256 delta = oracle.adjust(msg.sender);

    require(uint128(delta) <= MAX_BONUS, "cap");  // ← Checks only lower 128 bits

    credits[msg.sender] += delta;  // ← Adds full 256-bit value!
}
```

### The Bug

1. The oracle returns a `uint256` value (256-bit unsigned integer)
2. The contract casts it to `uint128` (128-bit) for the cap check: `uint128(delta) <= MAX_BONUS`
3. When casting a large `uint256` to `uint128`, only the **lower 128 bits** are kept (truncation overflow)
4. However, the full `uint256` value is then added to credits: `credits[msg.sender] += delta`

### Win Condition

The challenge is solved when: `vault.credits(player) > vault.MAX_BONUS()` (i.e., credits > 100 ether)

## Exploitation

### The Malicious Oracle

We create an oracle that returns a crafted value:

```solidity
function adjust(address user) external view returns (uint256) {
    // Returns: 2^128 + 50 ether
    return (uint256(1) << 128) + 50 ether;
}
```

### How It Works

Given our oracle returns: `2^128 + 50 ether`

1. **Casting to uint128**:
   - `uint128(2^128 + 50 ether)` → truncates to `50 ether`
   - The check passes: `50 ether <= 100 ether` ✓

2. **Adding to credits**:
   - `credits[msg.sender] += 2^128 + 50 ether`
   - Player receives `340282366920938463513374607431768211456` wei
   - Which is approximately `340,282,366,920,938,463,513 ether`

3. **Challenge solved**:
   - Credits: `~340 quintillion ETH`
   - MAX_BONUS: `100 ETH`
   - `340 quintillion > 100` ✓

## Exploit Steps

1. **Connect to blockchain instance**:
   - Call `/api/launch` to get RPC URL, private key, and contract addresses

2. **Deploy malicious oracle**:
   - Deploy `MaliciousOracle.sol` that returns `2^128 + 50 ether`

3. **Claim bonus**:
   - Call `vault.claimBonus(maliciousOracleAddress)`
   - The check sees `50 ether` but credits get `2^128 + 50 ether`

4. **Verify**:
   - Call `setup.isSolved()` returns `true`
   - Retrieve flag from `/api/flag?uuid=<uuid>`

## Key Takeaways

### The Vulnerability
- **Type Casting Overflow**: Explicit casts from larger to smaller integer types in Solidity truncate the value
- **Check-Use Mismatch**: The code checks a truncated value but uses the full value

### Real-World Impact
This type of vulnerability could allow:
- Bypassing deposit/withdrawal limits
- Minting unlimited tokens
- Draining contract funds
- Breaking protocol invariants

### Prevention
1. **Consistent Type Usage**: Use the same type for both checks and operations
2. **Safe Casting**: Use libraries like OpenZeppelin's SafeCast
3. **Input Validation**: Validate the full value before any type casting
4. **Trust Boundaries**: Never trust external contract returns without validation

### Correct Implementation
```solidity
function claimBonus(IOracleU oracle) external {
    uint256 delta = oracle.adjust(msg.sender);

    // Check the FULL value before using it
    require(delta <= MAX_BONUS, "cap");

    credits[msg.sender] += delta;
}
```

## Files

- [BonusVaultETH.sol](BonusVaultETH.sol) - Vulnerable vault contract
- [IOracleU.sol](IOracleU.sol) - Oracle interface
- [Setup.sol](Setup.sol) - Challenge setup
- [MaliciousOracle.sol](MaliciousOracle.sol) - Exploit oracle contract
- [exploit.py](exploit.py) - Python script to deploy and execute exploit
