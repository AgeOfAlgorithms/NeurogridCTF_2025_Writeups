// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

abstract contract RouterOnly {
    address public immutable router;
    constructor(address _router) { require(_router != address(0), "ROUTER=0"); router = _router; }
    modifier onlyRouter() { require(msg.sender == router, "ROUTER_ONLY"); _; }
}
