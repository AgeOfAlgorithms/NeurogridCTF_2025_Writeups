// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../Shop.sol";

contract DetailedGasTest is Test {
    Shop shop;

    function setUp() public {
        shop = new Shop();
        shop.initPrize();
    }

    function testFineGrainedSearch() public {
        bytes memory hookData = new bytes(100000);
        
        console.log("Testing gas limits from 110k to 130k:");
        
        for (uint256 g = 110000; g <= 130000; g += 100) {
            // Fresh shop for each test
            shop = new Shop();
            shop.initPrize();
            
            bool success = false;
            bool reverted = false;
            
            try shop.collectPrize{gas: g}(hookData) returns (bool result) {
                success = result;
                if (result) {
                    console.log("COLLECTED=true at gas:", g);
                }
            } catch {
                reverted = true;
            }
            
            if (!success && !reverted) {
                // Returned false without reverting
            }
        }
    }
    
    function testSpecificGas115k() public {
        bytes memory hookData = new bytes(100000);
        
        uint256 gasBefore = gasleft();
        bool result = shop.collectPrize{gas: 115000}(hookData);
        uint256 gasAfter = gasleft();
        
        console.log("Gas used:", gasBefore - gasAfter);
        console.log("Result:", result);
        
        require(result == true, "Expected collected=true");
    }
}
