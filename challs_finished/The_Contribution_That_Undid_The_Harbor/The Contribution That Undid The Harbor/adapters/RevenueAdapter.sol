// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../Adapter.sol";
import "../interfaces/IExecutor.sol";
import "../RevenueRouter.sol";
import "../ContributionNFT.sol";

contract RevenueAdapter is Adapter, IExecutor {
    function getSelectors() external pure override returns (bytes4[] memory arr) {
        arr = new bytes4[](7);
        arr[0] = this.collect.selector;
        arr[1] = this.claimFor.selector;
        arr[2] = this.creditOf.selector;
        arr[3] = this.claimByToken.selector;
        arr[4] = this.creditOfToken.selector;
        arr[6] = this.buyout.selector;
    }
    function name() external pure override returns (string memory) { return "RevenueAdapter"; }
    function version() external pure override returns (string memory) { return "1.2.0"; }

    function collect(uint256 portId) external payable {
        RevenueRouter(payable($().revenue)).collect{value: msg.value}(portId);
    }

    function claimFor(address account, address payable to) external onlyRouterOwner {
        RevenueRouter(payable($().revenue)).claimFor(account, to);
    }

    function creditOf(address account) external view returns (uint256) {
        return RevenueRouter(payable($().revenue)).credit(account);
    }

    function claimByToken(uint256 tokenId) external {
        RevenueRouter(payable($().revenue)).claimByToken(tokenId);
    }

    function buyout(uint256 tokenId) external {
        RevenueRouter(payable($().revenue)).buyout(tokenId);
        ContributionNFT($().cNFT).burn(tokenId);
    }

    function creditOfToken(uint256 tokenId) external view onlyRouterOwner returns (uint256) {
        return RevenueRouter(payable($().revenue)).creditOfToken(tokenId);
    }
}
