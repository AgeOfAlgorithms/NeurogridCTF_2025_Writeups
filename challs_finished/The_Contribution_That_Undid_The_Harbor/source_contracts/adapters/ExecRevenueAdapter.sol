// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../Adapter.sol";
import "../interfaces/IExecutor.sol";
import "../router/RouterStorage.sol";
import "../lib/Selectors.sol";

contract ExecRevenueAdapter is Adapter, IExecutor {
    function name() external pure override returns (string memory) { return "ExecRevenueAdapter"; }
    function version() external pure override returns (string memory) { return "1.1.0"; }

    function getSelectors() external pure override returns (bytes4[] memory arr) {
        arr = new bytes4[](8);
        arr[0] = this.registerInnerRevenue.selector;
        arr[1] = this.execCollect.selector;
        arr[2] = this.execClaimFor.selector;
        arr[3] = this.execCreditOf.selector;
        arr[4] = this.execBuyout.selector;
        arr[5] = this.execClaimByToken.selector;
        arr[6] = this.execCreditOfToken.selector; 
    }

    function registerInnerRevenue(bytes4[] calldata selectors, address[] calldata impls) external onlyRouterOwner {
        require(selectors.length == impls.length, "LEN");
        RouterStorage.S storage s = RouterStorage.state();
        for (uint256 i; i < selectors.length; i++) {
            address impl = impls[i];
            require(impl != address(0) && impl != address(this), "BAD_IMPL");
            s.innerRevenue[selectors[i]] = impl;
        }
    }

    function _inner(bytes4 sel) internal view returns (address impl) {
        impl = RouterStorage.state().innerRevenue[sel];
        require(impl != address(0), "NO_INNER");
    }
    function _fwd(address impl, bytes memory data) internal returns (bytes memory ret) {
        (bool ok, bytes memory r) = impl.delegatecall(data);
        if (!ok) assembly { revert(add(r, 0x20), mload(r)) }
        return r;
    }

    function execCollect(bytes calldata raw) external payable {
        uint256 portId = abi.decode(raw, (uint256));
        _fwd(_inner(Selectors.REV_COLLECT), abi.encodeWithSelector(Selectors.REV_COLLECT, portId));
    }

    function execClaimFor(bytes calldata raw) external onlyRouterOwner {
        (address account, address to) = abi.decode(raw, (address, address));
        _fwd(_inner(Selectors.REV_CLAIM_FOR), abi.encodeWithSelector(Selectors.REV_CLAIM_FOR, account, to));
    }

    function execBuyout(bytes calldata raw) external payable {
        (uint256 tokenId, address receiver) = abi.decode(raw, (uint256, address));
        _fwd(_inner(Selectors.REV_BUYOUT), abi.encodeWithSelector(Selectors.REV_BUYOUT, tokenId, receiver));
    }

    function execCreditOf(bytes calldata raw) external onlyRouterOwner returns (uint256) {
        address who = abi.decode(raw, (address));
        (bool ok, bytes memory ret) = _inner(Selectors.REV_CREDIT_OF).delegatecall(
            abi.encodeWithSelector(Selectors.REV_CREDIT_OF, who)
        );
        if (!ok) assembly { revert(add(ret, 0x20), mload(ret)) }
        return abi.decode(ret, (uint256));
    }

    function execClaimByToken(bytes calldata raw) external {
        uint256 tokenId = abi.decode(raw, (uint256));
        _fwd(_inner(Selectors.REV_CLAIM_BY_TOKEN), abi.encodeWithSelector(Selectors.REV_CLAIM_BY_TOKEN, tokenId));
    }

    function execCreditOfToken(bytes calldata raw) external returns (uint256) {
        uint256 tokenId = abi.decode(raw, (uint256));
        (bool ok, bytes memory ret) = _inner(Selectors.REV_CREDIT_OF_TOKEN).delegatecall(
            abi.encodeWithSelector(Selectors.REV_CREDIT_OF_TOKEN, tokenId)
        );
        if (!ok) assembly { revert(add(ret, 0x20), mload(ret)) }
        return abi.decode(ret, (uint256));
    }

    fallback() external payable {
        address impl = RouterStorage.state().innerRevenue[msg.sig];
        require(impl != address(0), "NO_INNER");
        bytes memory ret = _fwd(impl, msg.data);
        assembly { return(add(ret, 0x20), mload(ret)) }
    }
    receive() external payable {}
}
