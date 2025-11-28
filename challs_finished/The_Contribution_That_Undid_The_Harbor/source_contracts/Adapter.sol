// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./router/RouterStorage.sol";

interface IRouterOwner {
    function owner() external view returns (address);
}

abstract contract Adapter {
    function $() internal pure returns (RouterStorage.S storage s) { return RouterStorage.state(); }

    modifier onlyRouterOwner() {
        address _owner = IRouterOwner(address(this)).owner();
        require(msg.sender == _owner, "ONLY_OWNER");
        _;
    }

    modifier onlyEOA() {
        if (IRouterOwner(address(this)).owner() == msg.sender){
            _;
        }else { // owner using a special smart contract that using constructor that have 0 code length
            require(msg.sender == tx.origin && msg.sender.code.length > 0, "Only_Owner_EOA");
            _;
        }
    }

    function _sdc(address impl, bytes memory data) internal returns (bytes memory ret) {
        RouterStorage.S storage s = RouterStorage.state();
        require(impl != address(0), "NO_IMPL");
        require(s.deployerOf[impl] == IRouterOwner(address(this)).owner(), "UNTRUSTED_IMPL");
        (bool ok, bytes memory r) = impl.delegatecall(data);
        if (!ok) assembly { revert(add(r, 0x20), mload(r)) }
        return r;
    }
}
