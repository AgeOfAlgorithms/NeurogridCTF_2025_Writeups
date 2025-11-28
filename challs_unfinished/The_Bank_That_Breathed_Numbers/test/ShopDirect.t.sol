// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../Shop.sol";

contract ShopDirectTest is Test {
    Shop shop;

    function setUp() public {
        shop = new Shop();
        shop.initPrize();
    }

    function testDirectShop() public {
        console.log("=== Testing Direct Shop Call ===");
        console.log("");
        
        bytes memory hookData = new bytes(100000);
        
        // Test a few gas limits in the magic window
        uint256[] memory gasLimits = new uint256[](5);
        gasLimits[0] = 112000;
        gasLimits[1] = 113000;
        gasLimits[2] = 114000;
        gasLimits[3] = 115000;
        gasLimits[4] = 116000;
        
        for (uint256 i = 0; i < gasLimits.length; i++) {
            shop = new Shop();
            shop.initPrize();
            
            try shop.collectPrize{gas: gasLimits[i]}(hookData) returns (bool result) {
                console.log("Gas:", gasLimits[i], "Result:", result);
                if (result) {
                    console.log("  SUCCESS! This gas limit works!");
                }
            } catch {
                console.log("Gas:", gasLimits[i], "REVERTED");
            }
        }
    }
}
