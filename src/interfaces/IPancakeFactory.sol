// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IPancakeFactory
 * @notice Minimal interface for PancakeSwap V2 Factory (BSC).
 * @dev Used to check if a token-USDC pair exists for automatic path building.
 */
interface IPancakeFactory {
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}
