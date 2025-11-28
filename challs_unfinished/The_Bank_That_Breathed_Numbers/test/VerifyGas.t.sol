// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../Shop.sol";

contract VerifyGasTest is Test {
    Shop shop;

    function setUp() public {
        shop = new Shop();
        shop.initPrize();
    }

    function testGasLimit120k() public {
        bytes memory hookData = new bytes(100000);
        
        console.log("Before collectPrize:");
        console.log("  isPrizeActive:", shop.isPrizeActive());
        
        bool result = shop.collectPrize{gas: 120000}(hookData);
        
        console.log("After collectPrize:");
        console.log("  Result:", result);
        console.log("  isPrizeActive:", shop.isPrizeActive());
        
        require(result == true, "Expected true");
    }
    
    function testGasLimitRange() public {
        bytes memory hookData = new bytes(100000);
        
        // Test around 120k
        for (uint256 g = 115000; g <= 125000; g += 1000) {
            shop = new Shop();
            shop.initPrize();
            
            try shop.collectPrize{gas: g}(hookData) returns (bool result) {
                if (result) {
                    console.log("SUCCESS at gas:", g);
                }
            } catch {
                console.log("REVERT at gas:", g);
            }
        }
    }
}
