// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.4.0
pragma solidity ^0.8.27;

import {ERC20} from "../lib/ERC20/ERC20.sol";

contract HTB is ERC20 {
    mapping(address => bool) public isBlackListed;
    address public immutable owner;

    event AddedBlackList(address _user);
    event RemovedBlackList(address _user);

    constructor() ERC20("HackTheBank", "HTB") {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "not allowed");
        _mint(to, amount);
    }

    function addBlacklist(address _evilUser) external {
        require(_evilUser != address(0), "zero address cannot be blacklisted");
        if (_evilUser != msg.sender)
            require(msg.sender == owner, "not allowed");
        isBlackListed[_evilUser] = true;
        emit AddedBlackList(_evilUser);
    }

    function removeBlackList(address _clearedUser) external {
        isBlackListed[_clearedUser] = false;
        emit RemovedBlackList(_clearedUser);
    }

    function approve(
        address spender,
        uint256 amount
    ) public virtual override returns (bool) {
        require(
            !isBlackListed[msg.sender],
            "Blacklist: account is blacklisted"
        );
        _approve(_msgSender(), spender, amount);
        return true;
    }
}
