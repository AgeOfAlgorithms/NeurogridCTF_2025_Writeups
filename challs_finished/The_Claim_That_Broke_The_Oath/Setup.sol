// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BonusVaultETH} from "./BonusVaultETH.sol";

contract Setup {
    BonusVaultETH public immutable vault;
    address public player;

    constructor() payable {
        player = msg.sender;
        vault = new BonusVaultETH{value: msg.value}();
    }

    function isSolved() external view returns (bool) {
        return vault.credits(player) > vault.MAX_BONUS();
    }
}
