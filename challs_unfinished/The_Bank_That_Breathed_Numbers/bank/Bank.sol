// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "../interfaces/IERC20.sol";
import {IPermit2} from "../interfaces/IPermit2.sol";
import {ISignatureTransfer} from "../interfaces/ISignatureTransfer.sol";
import {AMM} from "./AMM.sol";

contract Bank {
    error Blacklisted(address user);
    error NotOwner();
    error InvalidAsset();
    error InsufficientBalance();
    error OfferNotFound();
    error OfferInactive();

    struct DepositInfo {
        uint256 amount;
    }

    struct LendOffer {
        address lender;
        address asset;
        uint256 principal;
        uint256 interest;
        uint256 expiry;
        bool active;
        address borrower;
    }

    IPermit2 public immutable permit2;
    AMM public amm;

    address public owner;

    mapping(address => bool) public blacklist;
    mapping(address => mapping(address => uint256)) public balances; // user => token => amount

    uint256 public nextOfferId;
    mapping(uint256 => LendOffer) public offers;

    event BlacklistSet(address indexed user, bool status);
    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount);
    event OfferCreated(
        uint256 indexed offerId,
        address indexed lender,
        address asset,
        uint256 principal,
        uint256 interest,
        uint256 expiry
    );
    event OfferCancelled(uint256 indexed offerId);
    event OfferTaken(uint256 indexed offerId, address indexed borrower);
    event Repaid(uint256 indexed offerId, address indexed borrower);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier notBlacklisted(address user) {
        if (blacklist[user]) revert Blacklisted(user);
        _;
    }

    constructor(IPermit2 _permit2) {
        owner = msg.sender;
        permit2 = _permit2;
    }

    function setAMM(AMM _amm) external onlyOwner {
        amm = _amm;
    }

    function setBlacklist(address user, bool status) external onlyOwner {
        blacklist[user] = status;
        emit BlacklistSet(user, status);
    }

    function depositToken(
        address token,
        uint256 amount
    ) external notBlacklisted(msg.sender) {
        if (token == address(0)) revert InvalidAsset();
        require(
            IERC20(token).transferFrom(msg.sender, address(this), amount),
            "TRANSFER_FROM_FAIL"
        );
        balances[msg.sender][token] += amount;
        emit Deposit(msg.sender, token, amount);
    }

    function depositTokenWithPermit(
        ISignatureTransfer.PermitTransferFrom calldata permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner_,
        bytes calldata signature
    ) external notBlacklisted(owner_) {
        address token = permit.permitted.token;
        if (token == address(0)) revert InvalidAsset();

        balances[owner_][token] += permit.permitted.amount;
        permit2.permitTransferFrom(permit, transferDetails, owner_, signature);

        emit Deposit(owner_, token, permit.permitted.amount);
    }

    function withdraw(
        address token,
        uint256 amount
    ) external notBlacklisted(msg.sender) {
        uint256 bal = balances[msg.sender][token];
        if (bal < amount) revert InsufficientBalance();
        balances[msg.sender][token] = bal - amount;
        require(IERC20(token).transfer(msg.sender, amount), "TRANSFER_FAIL");
        emit Withdraw(msg.sender, token, amount);
    }

    function createOffer(
        address asset,
        uint256 principal,
        uint256 interest,
        uint256 expiry
    ) external notBlacklisted(msg.sender) returns (uint256 offerId) {
        if (asset == address(0) || principal == 0) revert InvalidAsset();
        // lender must have deposited sufficient balance
        if (balances[msg.sender][asset] < principal)
            revert InsufficientBalance();

        offerId = ++nextOfferId;
        offers[offerId] = LendOffer({
            lender: msg.sender,
            asset: asset,
            principal: principal,
            interest: interest,
            expiry: expiry,
            active: true,
            borrower: address(0)
        });

        // lock principal
        balances[msg.sender][asset] -= principal;
        emit OfferCreated(
            offerId,
            msg.sender,
            asset,
            principal,
            interest,
            expiry
        );
    }

    function cancelOffer(uint256 offerId) external {
        LendOffer storage offer = offers[offerId];
        if (offer.lender == address(0)) revert OfferNotFound();
        if (offer.lender != msg.sender) revert NotOwner();
        if (!offer.active) revert OfferInactive();
        offer.active = false;
        // unlock funds
        balances[msg.sender][offer.asset] += offer.principal;
        emit OfferCancelled(offerId);
    }

    function takeOffer(uint256 offerId) external notBlacklisted(msg.sender) {
        LendOffer storage offer = offers[offerId];
        if (offer.lender == address(0)) revert OfferNotFound();
        if (!offer.active) revert OfferInactive();
        if (offer.borrower != address(0)) revert OfferInactive();
        require(
            block.timestamp <= offer.expiry || offer.expiry == 0,
            "EXPIRED"
        );

        offer.borrower = msg.sender;
        offer.active = false; // single-use

        // send principal to borrower from bank holdings
        require(
            IERC20(offer.asset).transfer(msg.sender, offer.principal),
            "TRANSFER_FAIL"
        );
        emit OfferTaken(offerId, msg.sender);
    }

    function repay(uint256 offerId) external notBlacklisted(msg.sender) {
        LendOffer storage offer = offers[offerId];
        if (offer.borrower != msg.sender) revert NotOwner();
        uint256 repayAmount = offer.principal + offer.interest;

        // borrower pays back to bank
        require(
            IERC20(offer.asset).transferFrom(
                msg.sender,
                address(this),
                repayAmount
            ),
            "TRANSFER_FROM_FAIL"
        );

        // credit lender balance
        balances[offer.lender][offer.asset] += repayAmount;
        emit Repaid(offerId, msg.sender);
    }

    receive() external payable {}
}
