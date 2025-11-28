// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

library Selectors {

    bytes4 internal constant PORT_CREATE = bytes4(keccak256("createPort(string)"));
    bytes4 internal constant PORT_SET_SPLITS = bytes4(keccak256("setSplits(uint16,uint16)"));
    bytes4 internal constant PORT_ISSUE_CONCESSION = bytes4(keccak256("issueConcession(uint256,address)"));

    bytes4 internal constant GOV_PROPOSE = bytes4(keccak256("propose(uint256,uint16,string)"));
    bytes4 internal constant GOV_ACCEPT_AND_MINT = bytes4(keccak256("acceptAndMint(uint256)"));
    bytes4 internal constant GOV_SETTLE_ALL_POOL_TO= bytes4(keccak256("settleAllPoolTo(address)"));

    bytes4 internal constant REV_COLLECT = bytes4(keccak256("collect(uint256)"));
    bytes4 internal constant REV_CLAIM_FOR = bytes4(keccak256("claimFor(address,address)"));
    bytes4 internal constant REV_CREDIT_OF = bytes4(keccak256("creditOf(address)"));
    bytes4 internal constant REV_BUYOUT = bytes4(keccak256("buyout(uint256)"));
    bytes4 constant REV_CLAIM_BY_TOKEN = bytes4(keccak256("claimByToken(uint256)"));
    bytes4 constant REV_CREDIT_OF_TOKEN = bytes4(keccak256("creditOfToken(uint256)"));
}
