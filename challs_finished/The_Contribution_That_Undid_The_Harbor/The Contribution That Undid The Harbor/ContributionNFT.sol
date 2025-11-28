// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./lib/ERC721Lite.sol";
import "./lib/RouterOnly.sol";
import "./lib/Errors.sol";

contract ContributionNFT is ERC721Lite, RouterOnly {
    struct Contribution { uint256 portId; uint256 proposalId; uint16 impactBps; }
    uint256 public nextId;
    mapping(uint256 => Contribution) public contribOf;

    constructor(address router_) ERC721Lite("PortContribution", "PORT-C") RouterOnly(router_) {}

    function mintFromProposal(address to, uint256 portId, uint256 proposalId, uint16 impactBps, string memory uri) external onlyRouter returns (uint256 id) {
        id = ++nextId;
        _mint(to, id);
        _setTokenURI(id, uri);
        contribOf[id] = Contribution({portId: portId, proposalId: proposalId, impactBps: impactBps});
    }

    function transferFrom(address, address, uint256) public pure override { revert Soulbound(); }
    function safeTransferFrom(address, address, uint256) public pure override { revert Soulbound(); }
    function safeTransferFrom(address, address, uint256, bytes calldata) public pure override { revert Soulbound(); }
    function burn(uint256 tokenId) external onlyRouter { 
        _burn(tokenId); 
    }

    function _beforeTokenTransfer(address from, address to, uint256 /* tokenId */) internal pure override {
        if (from != address(0) && to != address(0)) revert Soulbound();
    }
}
