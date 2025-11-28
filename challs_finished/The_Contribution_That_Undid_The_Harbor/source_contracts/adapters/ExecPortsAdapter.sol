// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../Adapter.sol";
import "../interfaces/IExecutor.sol";
import "../router/RouterStorage.sol";
import "../lib/Selectors.sol";

contract ExecPortsAdapter is Adapter, IExecutor {
    function name() external pure override returns (string memory) { return "ExecPortsAdapter"; }
    function version() external pure override returns (string memory) { return "1.0.0"; }

    function getSelectors() external pure override returns (bytes4[] memory arr) {
        arr = new bytes4[](4);
        arr[0] = this.registerInnerPorts.selector;
        arr[1] = this.execCreatePort.selector;
        arr[2] = this.execSetSplits.selector;
        arr[3] = this.execIssueConcession.selector;
    }

    function registerInnerPorts(bytes4[] calldata selectors, address[] calldata impls) external onlyRouterOwner {
        require(selectors.length == impls.length, "LEN");
        RouterStorage.S storage s = RouterStorage.state();
        for (uint256 i; i < selectors.length; i++) {
            address impl = impls[i];
            require(impl != address(0) && impl != address(this), "BAD_IMPL");
            s.innerPorts[selectors[i]] = impl;
        }
    }

    function _inner(bytes4 sel) internal view returns (address impl) {
        impl = RouterStorage.state().innerPorts[sel];
        require(impl != address(0), "NO_INNER");
    }

    function execCreatePort(bytes calldata raw) external returns (uint256 portId) {
        string memory portName = abi.decode(raw, (string));
        bytes memory data = abi.encodeWithSelector(Selectors.PORT_CREATE, portName);
        bytes memory ret  = _sdc(_inner(Selectors.PORT_CREATE), data);
        return abi.decode(ret, (uint256));
    }

    function execSetSplits(bytes calldata raw) external onlyRouterOwner {
        (uint16 opBps, uint16 contribBps) = abi.decode(raw, (uint16, uint16));
        bytes memory data = abi.encodeWithSelector(Selectors.PORT_SET_SPLITS, opBps, contribBps);
        _sdc(_inner(Selectors.PORT_SET_SPLITS), data);
    }

    function execIssueConcession(bytes calldata raw) external onlyRouterOwner {
        (uint256 portId, address to) = abi.decode(raw, (uint256, address));
        bytes memory data = abi.encodeWithSelector(Selectors.PORT_ISSUE_CONCESSION, portId, to);
        _sdc(_inner(Selectors.PORT_ISSUE_CONCESSION), data);
    }

    fallback() external payable {
        address impl = RouterStorage.state().innerPorts[msg.sig];
        require(impl != address(0), "NO_INNER");
        bytes memory ret = _sdc(impl, msg.data);
        assembly { return(add(ret, 0x20), mload(ret)) }
    }

    receive() external payable {}
}
