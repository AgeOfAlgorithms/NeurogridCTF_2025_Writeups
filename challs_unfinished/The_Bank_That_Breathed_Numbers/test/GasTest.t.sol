// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../Shop.sol";

contract GasTest is Test {
    Shop shop;

    function setUp() public {
        shop = new Shop();
        shop.initPrize();
    }

    function testFindGas() public {
        // 100KB hookData
        bytes memory hookData = new bytes(100000);
        
        // Cost to copy 100KB ~ 9375 gas.
        // Window size ~ 9375 gas.
        // Step 2000 should hit it.
        
        uint256 start = 100000;
        uint256 end = 30000000;
        uint256 step = 2000;
        
        for (uint256 g = start; g < end; g += step) {
            try shop.collectPrize{gas: g}(hookData) returns (bool result) {
                if (result) {
                    console.log("SUCCESS! Gas limit:", g);
                    return;
                }
            } catch {
                // Reverted
            }
        }
        
        console.log("No successful gas limit found in range");
    }
}
