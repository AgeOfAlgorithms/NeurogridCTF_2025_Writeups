// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IOracleU} from "./IOracleU.sol";

contract BonusVaultETH {
    uint128 public constant MAX_BONUS = 100 ether;

    mapping(address => uint256) public credits;

    constructor() payable {}
    receive() external payable {}

    function deposit() external payable {
        require(msg.value > 0, "zero");
        credits[msg.sender] += msg.value;
    }

    function claimBonus(IOracleU oracle) external {
        uint256 delta = oracle.adjust(msg.sender);

        require(uint128(delta) <= MAX_BONUS, "cap");

        credits[msg.sender] += delta;
    }

    function withdraw(uint256 amount) external {
        require(credits[msg.sender] >= amount, "insufficient credits");
        credits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
    }
}
