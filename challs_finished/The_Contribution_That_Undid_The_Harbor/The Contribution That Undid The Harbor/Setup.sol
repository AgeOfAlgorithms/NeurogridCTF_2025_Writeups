// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "./router/Router.sol";
import "./ContributionNFT.sol";
import "./CustomsConcessionNFT.sol";
import "./PortRegistry.sol";
import "./ProposalRegistry.sol";
import "./RevenueRouter.sol";
import "./adapters/PortsAdapter.sol";
import "./adapters/GovAdapter.sol";
import "./adapters/RevenueAdapter.sol";
import "./adapters/ExecPortsAdapter.sol";
import "./adapters/ExecGovAdapter.sol";
import "./adapters/ExecRevenueAdapter.sol";
import "./interfaces/IExecAdmin.sol";
import "./lib/Selectors.sol";

contract Setup {
    Router public router;
    address public bot;
    address public player;
    bool public run_market;

    ContributionNFT public cNFT;
    CustomsConcessionNFT public licNFT;
    PortRegistry public ports;
    ProposalRegistry public prop;
    RevenueRouter public revenue;

    PortsAdapter public portsAdapter;
    GovAdapter public govAdapter;
    RevenueAdapter public revenueAdapter;

    ExecPortsAdapter public execPorts;
    ExecGovAdapter public execGov;
    ExecRevenueAdapter public execRevenue;

    constructor() payable {
        bool ok;
        router = new Router(address(this));
        cNFT = new ContributionNFT(address(router));
        licNFT = new CustomsConcessionNFT(address(router));
        ports = new PortRegistry(address(router));
        prop = new ProposalRegistry(address(router));
        revenue = new RevenueRouter(address(router), licNFT, cNFT, ports);

        router.setModules(
            address(cNFT),
            address(licNFT),
            address(ports),
            address(prop),
            address(revenue)
        );

        portsAdapter = new PortsAdapter();
        govAdapter = new GovAdapter();
        revenueAdapter = new RevenueAdapter();

        execPorts = new ExecPortsAdapter();
        execGov = new ExecGovAdapter();
        execRevenue = new ExecRevenueAdapter();

        router.registerAdapter(address(execPorts), execPorts.getSelectors());
        router.registerAdapter(address(execGov), execGov.getSelectors());
        router.registerAdapter(address(execRevenue), execRevenue.getSelectors());

        {
            bytes4[] memory sPorts = portsAdapter.getSelectors();
            address[] memory implPorts = new address[](sPorts.length);
            for (uint i = 0; i < sPorts.length; i++) implPorts[i] = address(portsAdapter);
            IPortsAdmin(address(router)).registerInnerPorts(sPorts, implPorts);
        }
        {
            bytes4[] memory sGov = govAdapter.getSelectors();
            address[] memory implGov = new address[](sGov.length);
            for (uint i = 0; i < sGov.length; i++) implGov[i] = address(govAdapter);
            IGovAdmin(address(router)).registerInnerGov(sGov, implGov);
        }
        {
            bytes4[] memory sRev = revenueAdapter.getSelectors();
            address[] memory implRev = new address[](sRev.length);
            for (uint i = 0; i < sRev.length; i++) implRev[i] = address(revenueAdapter);
            IRevAdmin(address(router)).registerInnerRevenue(sRev, implRev);
        }
        {
            address[] memory impls = new address[](3);
            impls[0] = address(portsAdapter);
            impls[1] = address(govAdapter);
            impls[2] = address(revenueAdapter);
            router.trustImpls(impls, address(this));
        }
        {
            bytes4[] memory portsSelectors = new bytes4[](3);
            portsSelectors[0] = Selectors.PORT_CREATE;
            portsSelectors[1] = Selectors.PORT_SET_SPLITS;
            portsSelectors[2] = Selectors.PORT_ISSUE_CONCESSION;
            router.registerAdapter(address(execPorts), portsSelectors);
        }
        {
            bytes4[] memory govSelectors = new bytes4[](3);
            govSelectors[0] = Selectors.GOV_PROPOSE;
            govSelectors[1] = Selectors.GOV_ACCEPT_AND_MINT;
            govSelectors[2] = Selectors.GOV_SETTLE_ALL_POOL_TO;
            router.registerAdapter(address(execGov), govSelectors);
        }
        {
            bytes4[] memory revenueSelectors = new bytes4[](6);
            revenueSelectors[0] = Selectors.REV_COLLECT;
            revenueSelectors[1] = Selectors.REV_CLAIM_FOR;
            revenueSelectors[2] = Selectors.REV_CREDIT_OF;
            revenueSelectors[3] = Selectors.REV_BUYOUT;
            revenueSelectors[4] = Selectors.REV_CLAIM_BY_TOKEN;
            revenueSelectors[5] = Selectors.REV_CREDIT_OF_TOKEN;
            router.registerAdapter(address(execRevenue), revenueSelectors);
        }
        {
            bytes memory raw   = abi.encode(string("Edo Harbor"));
            bytes memory data = abi.encodeWithSelector(ExecPortsAdapter.execCreatePort.selector, raw);
            (ok,) = address(router).call(data);
            require(ok, "createPort failed");
        }
        {
            bytes memory raw   = abi.encode(uint16(8000), uint16(2000));
            bytes memory data = abi.encodeWithSelector(ExecPortsAdapter.execSetSplits.selector, raw);
            (ok,) = address(router).call(data);
            require(ok, "setSplits failed");
        }
        {
            bytes memory raw   = abi.encode(uint256(1), address(this));
            bytes memory data = abi.encodeWithSelector(ExecPortsAdapter.execIssueConcession.selector, raw);
            (ok,) = address(router).call(data);
            require(ok, "issueConcession failed");
        }
        {
            bytes memory data = abi.encodeWithSelector(
            ExecGovAdapter.execPropose.selector, abi.encode(uint256(1), uint16(10_000), string("ipfs://route-map-edo-winds")));
            (ok,) = address(router).call(data);
            require(ok, "Owner Propose Failed");
        }
        {
            bytes memory data = abi.encodeWithSelector(
            ExecGovAdapter.execAcceptAndMint.selector, abi.encode(uint256(1)));
            (ok,) = address(router).call(data);
            require(ok, "Owner Mint Failed");
        }

        (ok,) = payable(address(revenue)).call{value: 100 ether}("");
        require(ok, "FAILED_TO_SEND_ETH");
    }

    function admin() external view returns (address) {
        return address(this);
    }

    function runMarket() external {
        // This will be simulated the trading activities at the port
        require(!run_market, "Market already closed");
        bytes memory collect = abi.encodeWithSelector(
            ExecRevenueAdapter.execCollect.selector,
            abi.encode(uint256(1))
        );
        for(uint256 i = 0; i < 10; i++){
            (bool ok_market,) = address(router).call{value: 10 ether}(collect);
            require(ok_market);
        }
        run_market = true;
    }

    function register() external {
        player = msg.sender;
    }

    function isSolved() external view returns(bool){
        if(player.balance >= 200 ether && address(revenue).balance == 0 ether){
            return true;
        }else{
            return false;
        }
    }

    receive() external payable{}
    fallback() external payable{}
}
