// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./lib/RouterOnly.sol";

contract PortRegistry is RouterOnly {
    struct Port { string name; bool active; }
    uint256 public nextPortId;
    mapping(uint256 => Port) public ports;

    uint16 public operatorBps = 9000;
    uint16 public contributorsBps = 1000;

    constructor(address router_) RouterOnly(router_) {}

    function setSplits(uint16 opBps, uint16 contribBps) external onlyRouter {
        require(opBps + contribBps == 10000, "bps>100%");
        operatorBps = opBps; contributorsBps = contribBps;
    }
    function createPort(string calldata name) external onlyRouter returns (uint256 id) {
        id = ++nextPortId;
        ports[id] = Port({name: name, active: true});
    }
    function isActive(uint256 portId) external view returns (bool) {
        return ports[portId].active;
    }
    receive() external payable{}
}
