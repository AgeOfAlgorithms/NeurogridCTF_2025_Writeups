// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

struct WithdrawalRequest {
    uint256 shares;
    uint256 totalValue;
    uint256 sharePrice;
}

struct RedemptionQueue {
    mapping(uint256 => WithdrawalRequest) requests; // requestId => data
}
