// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./Asset.sol";
import "./interfaces/IAggregationRouterV5.sol";

/**
 * @title Deposit Adapter
 * @notice Accepts USDC tokens directly or swaps other tokens to USDC tokens via 1inch, then deposits into Asset.
 */
contract DepositAdapter is ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable USDC;
    Asset public immutable asset;
    address public immutable aggregationRouterV5;

    error ZeroAddress();
    error USDCAddressMismatch();

    event Deposit(address indexed chainAddress, uint256 usdcAmount);

    IERC20 private constant ETH_ADDRESS = IERC20(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
    IERC20 private constant ZERO_ADDRESS = IERC20(address(0));

    constructor(
        address _usdc,
        address _asset,
        address _aggregationRouterV5
    ) {
        if (_usdc == address(0) || _asset == address(0)) revert ZeroAddress();
        if (address(Asset(payable(_asset)).USDC()) != _usdc) revert USDCAddressMismatch();

        USDC = IERC20(_usdc);
        asset = Asset(payable(_asset));
        aggregationRouterV5 = _aggregationRouterV5;
    }

    /**
     * @notice Deposit to Asset: either USDC directly or swap token to USDC via 1inch then deposit.
     * @param token       Source token (use USDC for direct deposit).
     * @param amount      Amount to deposit or swap.
     * @param chainAddress Chain address for Asset.deposit.
     * @param exchangeData 1inch swap calldata (ignored when token == USDC).
     */
    function deposit(
        IERC20 token,
        uint256 amount,
        address chainAddress,
        bytes calldata exchangeData
    ) external payable nonReentrant returns (uint256) {
        uint256 returnAmount;
        uint256 beforeBalance = USDC.balanceOf(address(this));

        if (address(token) == address(USDC)) { // deposit USDC directly
            token.safeTransferFrom(msg.sender, address(this), amount);
            returnAmount = amount;
        } else {
            (
                ,
                IAggregationRouterV5.SwapDescription memory desc,
                ,
            ) = abi.decode(exchangeData[4:], (address, IAggregationRouterV5.SwapDescription, bytes, bytes));
            require(address(token) == address(desc.srcToken), "mismatch token and desc.srcToken");
            require(address(USDC) == address(desc.dstToken), "invalid desc.dstToken");
            require(amount == desc.amount, "mismatch amount and desc.amount");
            require(address(this) == desc.dstReceiver, "invalid desc.dstReceiver");

            // check if the token is native token
            bool isNativeToken = isNative(desc.srcToken);
            if (!isNativeToken) {  // deposit other ERC20 tokens 
                desc.srcToken.safeTransferFrom(msg.sender, address(this), desc.amount);

                // safeApprove requires unsetting the allowance first.
                desc.srcToken.forceApprove(aggregationRouterV5, 0);
                desc.srcToken.forceApprove(aggregationRouterV5, desc.amount);
            }

            // swap the token to USDC via 1inch
            (bool success, bytes memory returndata) = aggregationRouterV5.call{value: msg.value}(exchangeData);
            require(success, "exchange failed");

            // decode the return amount
            (returnAmount, ) = abi.decode(returndata, (uint256, uint256));
            require(returnAmount >= desc.minReturnAmount, "received USDC less than minReturnAmount");
        }

        // check if the swap is correct
        uint256 afterBalance = USDC.balanceOf(address(this));
        require(afterBalance == beforeBalance + returnAmount, "swap incorrect");

        // emit event
        emit Deposit(chainAddress, returnAmount);

        // deposit to Asset
        USDC.forceApprove(address(asset), returnAmount);
        asset.deposit(chainAddress, returnAmount);
        USDC.forceApprove(address(asset), 0);

        return returnAmount;
    }

    function isNative(IERC20 token_) internal pure returns (bool) {
        return (address(token_) == address(0) || address(token_) == address(ETH_ADDRESS));
    }
}
