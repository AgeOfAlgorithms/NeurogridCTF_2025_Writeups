// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

library RouterStorage {
    bytes32 internal constant SLOT = keccak256("virtuals.router.storage.v2");

    struct S {
        mapping(bytes4 => address) adapterOf;
        address cNFT;
        address licNFT;
        address ports;
        address prop;
        address revenue;

        mapping(bytes4 => address) innerPorts;
        mapping(bytes4 => address) innerGov;
        mapping(bytes4 => address) innerRevenue;

        mapping(address => address) deployerOf;
    }

    function state() internal pure returns (S storage s) {
        bytes32 slot = SLOT;
        assembly { s.slot := slot }
    }
}
