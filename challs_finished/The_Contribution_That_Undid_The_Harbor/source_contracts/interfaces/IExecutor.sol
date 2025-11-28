// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IExecutor {
    function getSelectors() external pure returns (bytes4[] memory);
    function name() external pure returns (string memory);
    function version() external pure returns (string memory);
}
