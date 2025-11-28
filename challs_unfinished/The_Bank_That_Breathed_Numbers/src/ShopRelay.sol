// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IShop {
    function collectPrize(bytes calldata data) external returns (bool);
}

/**
 * ShopRelay - Test calling Shop directly to isolate the gas issue
 */
contract ShopRelay {
    IShop public shop;
    bool public lastResult;

    constructor(address _shop) {
        shop = IShop(_shop);
    }

    /**
     * Call shop.collectPrize directly and store the result
     */
    function testShop(bytes calldata hookData, uint256 gasLimit) external {
        bool result = shop.collectPrize{gas: gasLimit}(hookData);
        lastResult = result;
    }

    /**
     * Call shop.collectPrize with try/catch to prevent revert
     */
    function testShopSafe(bytes calldata hookData, uint256 gasLimit) external {
        try shop.collectPrize{gas: gasLimit}(hookData) returns (bool result) {
            lastResult = result;
        } catch {
            lastResult = false;  // Call reverted
        }
    }
}
