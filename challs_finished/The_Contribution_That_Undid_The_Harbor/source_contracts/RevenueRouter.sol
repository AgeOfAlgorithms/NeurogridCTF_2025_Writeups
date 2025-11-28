// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./lib/ReentrancyGuard.sol";
import "./lib/RouterOnly.sol";
import "./CustomsConcessionNFT.sol";
import "./ContributionNFT.sol";
import "./PortRegistry.sol";

contract RevenueRouter is ReentrancyGuard, RouterOnly {
    struct PortContrib {
        uint256 totalImpactBps;
        mapping(address => uint256) impact;
    }

    mapping(address => uint256) public credit;
    mapping(uint256 => uint256) public creditToken;
    mapping(uint256 => uint256) public lastTokenOfPort;

    mapping(uint256 => PortContrib) private portDist;

    CustomsConcessionNFT public concession;
    ContributionNFT public contributionNFT;
    PortRegistry public registry;

    constructor(address router_, CustomsConcessionNFT _con, ContributionNFT _cNFT, PortRegistry _reg) RouterOnly(router_) { 
        concession = _con; contributionNFT = _cNFT; registry = _reg; 
    }

    function registerContribution(uint256 portId, address contributor, uint16 impactBps, uint256 tokenId) external onlyRouter{
        PortContrib storage pc = portDist[portId];
        pc.totalImpactBps += impactBps;
        pc.impact[contributor] += impactBps;
        require(tokenId != 0, "BAD_TOKEN");
        lastTokenOfPort[portId] = tokenId;
    }

    function claimFor(address account, address payable to) external onlyRouter nonReentrant {
        uint256 amt = credit[account];
        require(amt > 0, "no credit");
        credit[account] = 0;
        (bool ok,) = to.call{value: amt}("");
        require(ok, "xfer");
    }

    function claimByToken(uint256 tokenId) external onlyRouter nonReentrant {
        uint256 amt = creditToken[tokenId];
        require(amt > 0, "no credit");
        creditToken[tokenId] = 0;
        address payable to = payable(contributionNFT.ownerOf(tokenId));
        (bool ok,) = to.call{value: amt}("");
        require(ok, "xfer");
    }

    function creditOfToken(uint256 tokenId) external view returns (uint256) {
        return creditToken[tokenId];
    }

    function buyout(uint256 tokenId) external onlyRouter nonReentrant {
        require(creditToken[tokenId] == 0, "UNCLAIMED");
        require(address(this).balance >= 10 ether);
        address owner = contributionNFT.ownerOf(tokenId);
        require(owner != address(0), "NO_TOKEN");

        (bool ok,) = payable(owner).call{value: 10 ether}("");
        require(ok, "XFER");
    }
    function collect(uint256 portId) external payable onlyRouter nonReentrant {
        require(registry.isActive(portId), "inactive");
        address operator = concession.ownerOf(portId);
        require(operator != address(0), "no lic");

        uint256 opShare     = (msg.value * registry.operatorBps()) / 10_000;
        uint256 contribPool = (msg.value * registry.contributorsBps()) / 10_000;
        credit[operator] += opShare;
        creditToken[lastTokenOfPort[portId]] += contribPool; 
    }
    receive() external payable {}
    fallback() external payable {}
}
