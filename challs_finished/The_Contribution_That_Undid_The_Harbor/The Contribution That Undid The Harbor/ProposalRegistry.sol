// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./lib/RouterOnly.sol";

contract ProposalRegistry is RouterOnly {
    enum Status { None, Pending, Accepted, Rejected }

    struct Proposal {
        address proposer;
        uint256 portId;
        uint16 impactBps;
        uint8 status;
        string uri;
    }

    uint256 public lastId;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => uint256) public mustAcceptInBlock;

    constructor(address router_) RouterOnly(router_) {}

    function propose(address proposer, uint256 portId, uint16 impactBps, string calldata uri) external onlyRouter returns (uint256 pid){
        require(impactBps > 0 && impactBps <= 10000, "IMPACT");
        pid = ++lastId;
        proposals[pid] = Proposal(proposer, portId, impactBps, uint8(Status.Pending), uri);
        mustAcceptInBlock[pid] = block.number;
    }

    function accept(uint256 pid) external onlyRouter {
        Proposal storage p = proposals[pid];
        require(p.status == uint8(Status.Pending), "STATE");
        require(mustAcceptInBlock[pid] == block.number, "EXPIRED");
        p.status = uint8(Status.Accepted);
    }
    
    receive() external payable {}
}
