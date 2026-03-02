// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./Asset.sol";
import "./interfaces/IPancakeRouter02.sol";
import "./interfaces/IPancakeFactory.sol";

/**
 * @title Deposit Adapter
 * @notice Accepts USDC tokens directly or swaps other tokens to USDC via PancakeSwap (BSC), then deposits into Asset.
 * @dev Swap path is built on-chain: direct [token, USDC] if pair exists, else [token, WBNB, USDC].
 */
contract DepositAdapter is ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable USDC;
    Asset public immutable asset;
    IPancakeRouter02 public immutable pancakeRouter;
    IPancakeFactory public immutable pancakeFactory;
    /// @dev Wrapped native token (WBNB on BSC). Used for native BNB path and as middle hop when no direct token-USDC pair.
    address public immutable wbnb;

    error ZeroAddress();
    error USDCAddressMismatch();
    error InvalidAmountOrDeadline();
    error NoRoute();

    event Deposit(address indexed chainAddress, uint256 usdcAmount);

    constructor(
        address _usdc,
        address _asset,
        address _pancakeRouter,
        address _pancakeFactory,
        address _wbnb
    ) {
        if (_usdc == address(0) || _asset == address(0)) revert ZeroAddress();
        if (address(Asset(payable(_asset)).USDC()) != _usdc) revert USDCAddressMismatch();

        USDC = IERC20(_usdc);
        asset = Asset(payable(_asset));
        pancakeRouter = IPancakeRouter02(_pancakeRouter);
        pancakeFactory = IPancakeFactory(_pancakeFactory);
        wbnb = _wbnb;
    }

    /**
     * @notice Deposit to Asset: either USDC directly or swap token to USDC via PancakeSwap then deposit.
     * @param token        Source token (use USDC for direct deposit; use address(0) or 0xEee... for native BNB).
     * @param amount       Amount to deposit or swap (for native BNB must equal msg.value).
     * @param chainAddress Chain address for Asset.deposit.
     * @param minAmountOut Minimum USDC to receive (slippage protection). Ignored when token == USDC.
     * @param deadline     Swap deadline (unix timestamp). Ignored when token == USDC.
     * @dev Path is built on-chain: [token, USDC] if pair exists, else [token, WBNB, USDC]; for BNB use [WBNB, USDC].
     */
    function deposit(
        IERC20 token,
        uint256 amount,
        address chainAddress,
        uint256 minAmountOut,
        uint256 deadline
    ) external payable nonReentrant returns (uint256) {
        uint256 returnAmount;
        uint256 beforeBalance = USDC.balanceOf(address(this));

        if (address(token) == address(USDC)) {
            // Direct USDC deposit
            token.safeTransferFrom(msg.sender, address(this), amount);
            returnAmount = amount;
        } else {
            if (deadline < block.timestamp) revert InvalidAmountOrDeadline();

            if (address(token) == wbnb) {
                if (amount != msg.value) revert InvalidAmountOrDeadline();
                address[] memory path = _buildPathForNative();
                uint256[] memory amounts = pancakeRouter.swapExactETHForTokens{value: msg.value}(
                    minAmountOut,
                    path,
                    address(this),
                    deadline
                );
                returnAmount = amounts[amounts.length - 1];
            } else {
                address[] memory path = _buildPath(address(token));
                token.safeTransferFrom(msg.sender, address(this), amount);
                token.forceApprove(address(pancakeRouter), 0);
                token.forceApprove(address(pancakeRouter), amount);
                uint256[] memory amounts = pancakeRouter.swapExactTokensForTokens(
                    amount,
                    minAmountOut,
                    path,
                    address(this),
                    deadline
                );
                returnAmount = amounts[amounts.length - 1];
            }
        }

        uint256 afterBalance = USDC.balanceOf(address(this));
        require(afterBalance == beforeBalance + returnAmount, "swap incorrect");

        emit Deposit(chainAddress, returnAmount);

        USDC.forceApprove(address(asset), returnAmount);
        asset.deposit(chainAddress, returnAmount);
        USDC.forceApprove(address(asset), 0);

        return returnAmount;
    }

    /// @dev Path for native BNB: [WBNB, USDC].
    function _buildPathForNative() internal view returns (address[] memory path) {
        path = new address[](2);
        path[0] = wbnb;
        path[1] = address(USDC);
    }

    /// @dev Path for ERC20: [token, USDC] if pair exists, else [token, WBNB, USDC]. Reverts if no route.
    function _buildPath(address tokenIn) internal view returns (address[] memory path) {
        if (pancakeFactory.getPair(tokenIn, address(USDC)) != address(0)) {
            path = new address[](2);
            path[0] = tokenIn;
            path[1] = address(USDC);
        } else if (pancakeFactory.getPair(tokenIn, wbnb) != address(0)) {
            path = new address[](3);
            path[0] = tokenIn;
            path[1] = wbnb;
            path[2] = address(USDC);
        } else {
            revert NoRoute();
        }
    }

    /**
     * @notice Get the expected USDC amount out for a given token and amount (no swap, view only).
     * @param token   Source token (use USDC address for 1:1; use wbnb for native BNB).
     * @param amountIn Amount of token to quote.
     * @return usdcAmountOut Expected USDC amount received if swapping via PancakeSwap (same path logic as deposit).
     */
    function getUsdcAmountOut(address token, uint256 amountIn) external view returns (uint256 usdcAmountOut) {
        if (token == address(USDC)) {
            return amountIn;
        }
        address[] memory path;
        if (token == wbnb) {
            path = _buildPathForNative();
        } else {
            path = _buildPath(token);
        }
        uint256[] memory amounts = pancakeRouter.getAmountsOut(amountIn, path);
        return amounts[amounts.length - 1];
    }
}
