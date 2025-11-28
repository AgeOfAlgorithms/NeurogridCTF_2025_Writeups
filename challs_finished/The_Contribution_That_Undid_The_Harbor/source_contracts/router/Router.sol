// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../lib/Ownable.sol";
import "./RouterStorage.sol";

contract Router is Ownable {
    using RouterStorage for RouterStorage.S;

    constructor(address initialOwner) Ownable(initialOwner) {}

    function setModules(
        address cNFT,
        address licNFT,
        address ports,
        address prop,
        address revenue
    ) external onlyOwner {
        RouterStorage.S storage s = RouterStorage.state();
        s.cNFT = cNFT;
        s.licNFT = licNFT;
        s.ports = ports;
        s.prop = prop;
        s.revenue = revenue;
    }

    function registerAdapter(address adapter, bytes4[] memory selectors) external onlyOwner {
        RouterStorage.S storage s = RouterStorage.state();
        uint256 n = selectors.length;
        for (uint256 i; i < n; i++) {
            s.adapterOf[selectors[i]] = adapter;
        }
        s.deployerOf[adapter] = owner();
    }

    function trustImpls(address[] calldata impls, address deployer) external onlyOwner {
        RouterStorage.S storage s = RouterStorage.state();
        uint256 n = impls.length;
        for (uint256 i; i < n; i++) {
            s.deployerOf[impls[i]] = deployer;
        }
    }

    fallback() external payable {
        RouterStorage.S storage s = RouterStorage.state();
        address impl = s.adapterOf[msg.sig];
        require(impl != address(0), "NO_ADAPTER");
        require(s.deployerOf[impl] == owner(), "UNTRUSTED_IMPL");
        (bool ok, bytes memory ret) = impl.delegatecall(msg.data);
        if (!ok) assembly { revert(add(ret, 0x20), mload(ret)) }
        assembly { return(add(ret, 0x20), mload(ret)) }
    }

    receive() external payable {}
}
