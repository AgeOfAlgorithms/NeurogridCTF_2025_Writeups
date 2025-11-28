// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRouter {
    function propose(uint256 portId, uint16 impactBps, string calldata uri) external returns (uint256);
    function acceptAndMint(uint256 proposalId) external;
}

contract Helper {
    // This contract will be delegated to via EIP-7702
    // When called, msg.sender will be the EOA, tx.origin will be the EOA
    // And the EOA will have code (this contract's code via delegation)

    function batchMint(address router, uint256 portId, uint16 impactBps, uint256 count) external {
        IRouter r = IRouter(router);
        for (uint256 i = 0; i < count; i++) {
            uint256 pid = r.propose(portId, impactBps, string(abi.encodePacked("ipfs://batch-", i)));
            r.acceptAndMint(pid);
        }
    }

    // CRITICAL: Need receive function to accept ETH when delegated via EIP-7702
    receive() external payable {}
    fallback() external payable {}
}
