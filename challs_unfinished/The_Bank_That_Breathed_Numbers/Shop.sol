// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Shop {
    uint256 public lastPrizeId;
    bool public isPrizeActive;
    bytes public encodedPrize;
    address private owner;

    constructor() {
        owner = msg.sender;
    }

    function initPrize() external {
        require(msg.sender == owner, "owner only");
        uint256 id = ++lastPrizeId;
        bytes memory encoded = abi.encodePacked(id, uint256(300 ether));
        encodedPrize = encoded;
        isPrizeActive = true;
    }

    function collectPrize(bytes calldata hookData) external returns (bool) {
        require(isPrizeActive, "initPrize first");

        bytes memory enc = abi.encodePacked(
            encodedPrize,
            hookData.length,
            hookData
        );

        assembly {
            let dl := mload(enc)
            let nenc := mload(0x40)
            mstore(0x40, add(nenc, add(0x20, dl)))
            let called := staticcall(
                gas(),
                4,
                enc,
                add(0x20, dl),
                nenc,
                add(0x20, dl)
            )
            let amount := mload(add(nenc, 0x54))
            if gt(amount, 0) {
                mstore(add(nenc, 0x54), sub(amount, 1))
            }
            if eq(amount, 0) {
                mstore(0x00, 1)
                return(0x00, 0x20)
            }
        }

        (uint256 id, uint256 amount) = abi.decode(
            encodedPrize,
            (uint256, uint256)
        );

        bytes memory newEncodedPrize = abi.encodePacked(id, amount - 1);
        encodedPrize = newEncodedPrize;

        return false;
    }
}
