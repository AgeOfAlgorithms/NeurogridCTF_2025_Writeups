// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Bank} from "./bank/Bank.sol";
import {Permit2} from "./lib/permit2/Permit2.sol";
import {IPermit2} from "./interfaces/IPermit2.sol";
import {WETH} from "./tokens/WETH.sol";
import {HTB} from "./tokens/HTB.sol";
import {USDC} from "./tokens/USDC.sol";
import {AMM} from "./bank/AMM.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {Shop} from "./Shop.sol";

contract Setup {
    Bank public immutable bank;
    AMM public immutable amm;
    IPermit2 public immutable permit2;
    Shop public immutable shop;

    WETH public immutable weth;
    HTB public immutable htb;
    USDC public immutable usdc;

    bool public collected;
    address public player;

    constructor() payable {
        permit2 = IPermit2(address(new Permit2()));

        weth = new WETH();
        htb = new HTB();
        usdc = new USDC();

        bank = new Bank(permit2);
        amm = new AMM(IERC20(address(htb)), IERC20(address(usdc)));
        shop = new Shop();
        shop.initPrize();

        htb.mint(address(this), 1_000_000 ether);
        htb.approve(address(amm), type(uint256).max);

        usdc.mint(address(this), 1_000_000 ether);
        usdc.approve(address(amm), type(uint256).max);

        amm.addLiquidity(120_000 ether, 120_000 ether);
        bank.setAMM(amm);

        weth.deposit{value: 300 ether}();
        weth.approve(address(bank), type(uint256).max);
        bank.depositToken(address(weth), weth.balanceOf(address(this)));
    }

    function setPlayer(address _player) external {
        require(player == address(0), "player already set");
        player = _player;
        htb.mint(player, 1);
        usdc.mint(player, 1);
    }

    function collectPrize(bytes calldata data) external {
        if (shop.collectPrize(data)) {
            collected = true;
        }
    }

    function isSolved() external view returns (bool) {
        return
            weth.balanceOf(address(bank)) == 0 &&
            address(bank).balance == 0 &&
            htb.balanceOf(address(amm)) == 0 &&
            usdc.balanceOf(address(amm)) == 0 &&
            collected;
    }
}
