// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../Adapter.sol";
import "../interfaces/IExecutor.sol";
import "../router/RouterStorage.sol";
import "../lib/Selectors.sol";

contract ExecGovAdapter is Adapter, IExecutor {
    function name() external pure override returns (string memory) { return "ExecGovAdapter"; }
    function version() external pure override returns (string memory) { return "1.0.0"; }

    function getSelectors() external pure override returns (bytes4[] memory arr) {
        arr = new bytes4[](4);
        arr[0] = this.registerInnerGov.selector;
        arr[1] = this.execPropose.selector;
        arr[2] = this.execAcceptAndMint.selector;
        arr[3] = this.execSettleAllPoolTo.selector;
    }

    function registerInnerGov(bytes4[] calldata selectors, address[] calldata impls) external onlyRouterOwner {
        require(selectors.length == impls.length, "LEN");
        RouterStorage.S storage s = RouterStorage.state();
        for (uint256 i; i < selectors.length; i++) {
            address impl = impls[i];
            require(impl != address(0) && impl != address(this), "BAD_IMPL");
            s.innerGov[selectors[i]] = impl;
        }
    }

    function _inner(bytes4 sel) internal view returns (address impl) {
        impl = RouterStorage.state().innerGov[sel];
        require(impl != address(0), "NO_INNER");
    }

    function execPropose(bytes calldata raw) external returns (uint256 proposalId) {
        (uint256 portId, uint16 impactBps, string memory uri) = abi.decode(raw, (uint256, uint16, string));
        bytes memory data = abi.encodeWithSelector(Selectors.GOV_PROPOSE, portId, impactBps, uri);
        bytes memory ret  = _sdc(_inner(Selectors.GOV_PROPOSE), data);
        return abi.decode(ret, (uint256));
    }

    function execAcceptAndMint(bytes calldata raw) external onlyRouterOwner {
        uint256 proposalId = abi.decode(raw, (uint256));
        bytes memory data  = abi.encodeWithSelector(Selectors.GOV_ACCEPT_AND_MINT, proposalId);
        _sdc(_inner(Selectors.GOV_ACCEPT_AND_MINT), data);
    }

    function execSettleAllPoolTo(bytes calldata raw) external onlyRouterOwner {
        address to = abi.decode(raw, (address));
        bytes memory data = abi.encodeWithSelector(Selectors.GOV_SETTLE_ALL_POOL_TO, to);
        _sdc(_inner(Selectors.GOV_SETTLE_ALL_POOL_TO), data);
    }

    fallback() external payable {
        address impl = RouterStorage.state().innerGov[msg.sig];
        require(impl != address(0), "NO_INNER");
        bytes memory ret = _sdc(impl, msg.data);
        assembly { return(add(ret, 0x20), mload(ret)) }
    }

    receive() external payable {}
}
