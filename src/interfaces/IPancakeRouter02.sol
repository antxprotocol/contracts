// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IPancakeRouter02
 * @notice Minimal interface for PancakeSwap V2 Router (BSC).
 * @dev Used for token swap in DepositAdapter.
 */
interface IPancakeRouter02 {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);

    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts);
}
