// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

abstract contract ReentrancyGuard {
    uint256 private constant _NOT = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT;

    modifier nonReentrant() {
        require(_status != _ENTERED, "REENTRANCY");
        _status = _ENTERED;
        _;
        _status = _NOT;
    }
}
