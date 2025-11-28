// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface IPortsAdmin {
    function registerInnerPorts(bytes4[] calldata selectors, address[] calldata impls) external;
}

interface IGovAdmin {
    function registerInnerGov(bytes4[] calldata selectors, address[] calldata impls) external;
}

interface IRevAdmin {
    function registerInnerRevenue(bytes4[] calldata selectors, address[] calldata impls) external;
}
