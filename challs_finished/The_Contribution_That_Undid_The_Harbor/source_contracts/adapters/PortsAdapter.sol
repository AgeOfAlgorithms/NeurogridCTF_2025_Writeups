// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../Adapter.sol";
import "../interfaces/IExecutor.sol";
import "../PortRegistry.sol";
import "../CustomsConcessionNFT.sol";

contract PortsAdapter is Adapter, IExecutor {
    function getSelectors() external pure override returns (bytes4[] memory arr) {
        arr = new bytes4[](3);
        arr[0] = this.createPort.selector;
        arr[1] = this.setSplits.selector;
        arr[2] = this.issueConcession.selector;
    }

    function name() external pure override returns (string memory) { return "PortsAdapter"; }
    function version() external pure override returns (string memory) { return "1.1.1"; }

    function createPort(string calldata portName) external onlyRouterOwner returns (uint256 portId) {
        portId = PortRegistry(payable($().ports)).createPort(portName);
    }

    function setSplits(uint16 operatorBps, uint16 contributorsBps) external onlyRouterOwner {
        PortRegistry(payable($().ports)).setSplits(operatorBps, contributorsBps);
    }

    function issueConcession(uint256 portId, address to) external onlyRouterOwner {
        CustomsConcessionNFT(payable($().licNFT)).mintConcession(to, portId);
    }
}
