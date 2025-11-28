// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "../interfaces/IERC20.sol";
import {ProcessingMode} from "./ProcessingMode.sol";
import {RedemptionQueue, WithdrawalRequest} from "./QueueTypes.sol";

library MathLib {
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denom
    ) internal pure returns (uint256) {
        return (a * b) / denom;
    }
}

contract AMM {
    using MathLib for uint256;

    IERC20 public immutable token0;
    IERC20 public immutable token1;
    uint112 public reserve0;
    uint112 public reserve1;
    uint32 public blockTimestampLast;

    uint256 public lpTotalSupply;
    mapping(address => uint256) public lpBalanceOf;

    uint256 public constant PRECISION = 1e18;
    ProcessingMode public processingMode = ProcessingMode.RequestPrice;
    mapping(address => uint128) internal _requestIds;
    RedemptionQueue internal _queue;
    uint256 public totalQueuedShares;

    event Mint(
        address indexed provider,
        uint256 amount0,
        uint256 amount1,
        uint256 liquidity
    );
    event Burn(
        address indexed provider,
        uint256 amount0,
        uint256 amount1,
        uint256 liquidity
    );
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    event RequestQueued(
        address indexed controller,
        uint128 requestId,
        uint256 shares,
        uint256 price
    );
    event RequestReduced(
        address indexed controller,
        uint128 requestId,
        uint256 sharesFilled
    );
    event RequestFulfilled(
        address indexed controller,
        uint128 requestId,
        uint256 shares,
        uint256 assetsOut
    );

    constructor(IERC20 _token0, IERC20 _token1) {
        token0 = _token0;
        token1 = _token1;
    }

    function _update(uint256 balance0, uint256 balance1) private {
        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = uint32(block.timestamp);
        emit Sync(reserve0, reserve1);
    }

    function addLiquidity(
        uint256 amount0,
        uint256 amount1
    ) external returns (uint256 liquidity) {
        require(amount0 > 0 && amount1 > 0, "ZERO");
        require(token0.transferFrom(msg.sender, address(this), amount0), "TF0");
        require(token1.transferFrom(msg.sender, address(this), amount1), "TF1");

        uint256 _reserve0 = reserve0;
        uint256 _reserve1 = reserve1;
        if (lpTotalSupply == 0) {
            liquidity = MathLib.mulDiv(amount0, amount1, 1e18) + 1000;
        } else {
            uint256 liq0 = (amount0 * lpTotalSupply) / _reserve0;
            uint256 liq1 = (amount1 * lpTotalSupply) / _reserve1;
            liquidity = liq0 < liq1 ? liq0 : liq1;
        }
        require(liquidity > 0, "INSUFFICIENT_LIQ");
        lpTotalSupply += liquidity;
        lpBalanceOf[msg.sender] += liquidity;

        _update(_reserve0 + amount0, _reserve1 + amount1);
        emit Mint(msg.sender, amount0, amount1, liquidity);
    }

    function removeLiquidity(
        uint256 liquidity,
        address to
    ) external returns (uint256 amount0, uint256 amount1) {
        require(
            liquidity > 0 && lpBalanceOf[msg.sender] >= liquidity,
            "LP_LOW"
        );
        uint256 _reserve0 = reserve0;
        uint256 _reserve1 = reserve1;
        amount0 = (liquidity * _reserve0) / lpTotalSupply;
        amount1 = (liquidity * _reserve1) / lpTotalSupply;
        lpBalanceOf[msg.sender] -= liquidity;
        lpTotalSupply -= liquidity;
        require(token0.transfer(to, amount0), "TRF0");
        require(token1.transfer(to, amount1), "TRF1");
        _update(_reserve0 - amount0, _reserve1 - amount1);
        emit Burn(msg.sender, amount0, amount1, liquidity);
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        require(amount0Out == 0 || amount1Out == 0, "ONE_SIDE");
        require(amount0Out < reserve0 && amount1Out < reserve1, "RES");

        uint256 balance0Before = token0.balanceOf(address(this));
        uint256 balance1Before = token1.balanceOf(address(this));

        if (amount0Out > 0) require(token0.transfer(to, amount0Out), "O0");
        if (amount1Out > 0) require(token1.transfer(to, amount1Out), "O1");

        uint256 balance0After = token0.balanceOf(address(this));
        uint256 balance1After = token1.balanceOf(address(this));

        uint256 amount0In = balance0After + amount0Out > balance0Before
            ? balance0After + amount0Out - balance0Before
            : 0;
        uint256 amount1In = balance1After + amount1Out > balance1Before
            ? balance1After + amount1Out - balance1Before
            : 0;
        require(amount0In > 0 || amount1In > 0, "NO_IN");

        uint256 bal0Adj = (balance0After * 1000) - (amount0In * 3);
        uint256 bal1Adj = (balance1After * 1000) - (amount1In * 3);
        require(
            bal0Adj * bal1Adj >=
                uint256(reserve0) * uint256(reserve1) * 1000 ** 2,
            "K"
        );

        _update(balance0After, balance1After);
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    function redeemRequest(
        uint256 shares,
        uint256 sharePrice
    ) external returns (uint128 requestId) {
        require(shares > 0, "ZERO");
        totalQueuedShares += shares;
        uint128 current = _requestIds[msg.sender];
        if (current == 0) {
            requestId = uint128(
                uint256(keccak256(abi.encodePacked(msg.sender, block.number)))
            );
            _requestIds[msg.sender] = requestId;
            WithdrawalRequest storage request = _queue.requests[requestId];
            request.shares = shares;
            if (processingMode == ProcessingMode.RequestPrice) {
                request.totalValue = shares.mulDiv(sharePrice, PRECISION);
                request.sharePrice = sharePrice;
            }
        } else {
            requestId = current;
            WithdrawalRequest storage request = _queue.requests[current];
            request.shares += shares;
            if (processingMode == ProcessingMode.RequestPrice) {
                request.totalValue += shares.mulDiv(sharePrice, PRECISION);
                request.sharePrice = request.totalValue.mulDiv(
                    PRECISION,
                    request.shares
                );
            }
        }
        emit RequestQueued(msg.sender, requestId, shares, sharePrice);
    }

    function fulfillRedeemPartial(
        uint256 sharesToFill,
        bool payToken0
    ) external {
        uint128 requestId = _requestIds[msg.sender];
        require(requestId != 0, "NO_REQ");
        WithdrawalRequest storage request = _queue.requests[requestId];
        require(request.shares >= sharesToFill, ">SHARES");
        uint256 price = processingMode == ProcessingMode.RequestPrice
            ? request.sharePrice
            : PRECISION;
        uint256 assetsOut = sharesToFill.mulDiv(price, PRECISION);

        if (payToken0) {
            require(token0.transfer(msg.sender, assetsOut), "TRF0");
            _update(reserve0 - uint112(assetsOut), reserve1);
        } else {
            require(token1.transfer(msg.sender, assetsOut), "TRF1");
            _update(reserve0, reserve1 - uint112(assetsOut));
        }

        _reduce(msg.sender, sharesToFill); // BUG
        emit RequestFulfilled(msg.sender, requestId, sharesToFill, assetsOut);
    }

    function _reduce(
        address controller,
        uint256 shares
    ) internal returns (uint256 remainingShares) {
        uint128 requestId = _requestIds[controller];
        require(requestId != 0, "NoQueueRequest");
        uint256 currentShares = _queue.requests[requestId].shares;
        require(
            shares <= currentShares && currentShares != 0,
            "InsufficientShares"
        );
        remainingShares = currentShares - shares;
        totalQueuedShares -= shares;
        if (remainingShares == 0) {
            delete _queue.requests[requestId];
            _requestIds[controller] = 0;
        } else {
            _queue.requests[requestId].shares = remainingShares;
        }
        emit RequestReduced(controller, requestId, shares);
    }

    function getRequest(
        address controller
    ) external view returns (uint128 id, WithdrawalRequest memory req) {
        id = _requestIds[controller];
        req = _queue.requests[id];
    }
}
