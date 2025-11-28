// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./lib/ERC721Lite.sol";
import "./lib/RouterOnly.sol";

contract CustomsConcessionNFT is ERC721Lite, RouterOnly {
    constructor(address router_) ERC721Lite("CustomsConcession", "PORT-LIC") RouterOnly(router_) {}
    function mintConcession(address to, uint256 portId) external onlyRouter { _mint(to, portId); }
}
