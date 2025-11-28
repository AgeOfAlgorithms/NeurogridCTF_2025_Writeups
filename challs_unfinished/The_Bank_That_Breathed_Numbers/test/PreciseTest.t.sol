// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../Shop.sol";

contract PreciseTest is Test {
    Shop shop;

    function setUp() public {
        shop = new Shop();
        shop.initPrize();
    }

    function testEveryGasFrom0to200k() public {
        bytes memory hookData = new bytes(100000);
        
        uint256 firstSuccess = 0;
        uint256 lastSuccess = 0;
        
        for (uint256 g = 10000; g <= 200000; g += 500) {
            shop = new Shop();
            shop.initPrize();
            
            try shop.collectPrize{gas: g}(hookData) returns (bool result) {
                if (result) {
                    if (firstSuccess == 0) {
                        firstSuccess = g;
                    }
                    lastSuccess = g;
                }
            } catch {}
        }
        
        console.log("First successful gas limit:", firstSuccess);
        console.log("Last successful gas limit:", lastSuccess);
    }
}
