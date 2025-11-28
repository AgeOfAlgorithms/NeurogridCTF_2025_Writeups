// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../Adapter.sol";
import "../interfaces/IExecutor.sol";

import "../ProposalRegistry.sol";
import "../ContributionNFT.sol";
import "../RevenueRouter.sol";

contract GovAdapter is Adapter, IExecutor {
    function getSelectors() external pure override returns (bytes4[] memory arr) {
        arr = new bytes4[](2);
        arr[0] = this.propose.selector;
        arr[1] = this.acceptAndMint.selector;
    }
    function name() external pure override returns (string memory) { return "GovAdapter"; }
    function version() external pure override returns (string memory) { return "1.2.0"; }

    function propose(uint256 portId, uint16 impactBps, string calldata uri)external returns (uint256 pid) {
        pid = ProposalRegistry(payable($().prop)).propose(msg.sender, portId, impactBps, uri);
    }

    function acceptAndMint(uint256 proposalId) external onlyEOA{
        ProposalRegistry pr = ProposalRegistry(payable($().prop));
        pr.accept(proposalId);
        (address proposer, uint256 portId, uint16 impactBps, , string memory uri) = pr.proposals(proposalId);
        uint256 tokenId = ContributionNFT($().cNFT).mintFromProposal(proposer, portId, proposalId, impactBps, uri);
        RevenueRouter(payable($().revenue)).registerContribution(portId, proposer, impactBps, tokenId);
    }

}
