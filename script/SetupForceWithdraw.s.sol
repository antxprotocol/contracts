// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

/**
 * @title SetupForceWithdrawScript
 * @notice Script to set up user and asset data for force withdraw testing
 * @dev This script sets up:
 *   1. Coin information (defaultCollateralCoinId)
 *   2. Subaccount information (subaccountId and chainAddress)
 *   3. PerpetualAsset information (crossCollateralAmount for available balance)
 *   4. Updates lastBatchTime to enable force withdraw (after time lock)
 * 
 * Usage:
 *   forge script script/SetupForceWithdraw.s.sol:SetupForceWithdrawScript --rpc-url <RPC_URL> --broadcast
 * 
 * Required environment variables:
 *   - PRIVATE_KEY: Private key for signing transactions (must be settlement operator)
 *   - CURRENT_ENV: "devnet", "testnet", or "mainnet"
 *   - USER_ADDRESS: User address (bytes32 format, derived from private key if not provided)
 *   - SUBACCOUNT_ID: Subaccount ID (default: 1000000009)
 *   - COLLATERAL_AMOUNT: Collateral amount in wei (default: 1000000000)
 */

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";
import "../src/margin/MarginAsset.sol";

contract SetupForceWithdrawScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address proxyAddress;
        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            proxyAddress = vm.envAddress("DEVNET_ASSET_PROXY_ADDRESS");
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            proxyAddress = vm.envAddress("TESTNET_ASSET_PROXY_ADDRESS");
        } else {
            proxyAddress = vm.envAddress("MAINNET_ASSET_PROXY_ADDRESS");
        }
        console.log("Asset proxy address at:", address(proxyAddress));
        Asset asset = Asset(payable(proxyAddress));

        // Get user address from private key or env
        bytes32 user;
        try vm.envAddress("USER_ADDRESS") returns (address envUserAddr) {
            user = bytes32(uint256(uint160(envUserAddr)));
            console.log("User address from env:", envUserAddr);
        } catch {
            // Derive from private key used for force withdraw
            try vm.envUint("FORCE_WITHDRAW_PRIVATE_KEY") returns (uint256 forceWithdrawKey) {
                address userAddr = vm.addr(forceWithdrawKey);
                user = bytes32(uint256(uint160(userAddr)));
                console.log("User address derived from FORCE_WITHDRAW_PRIVATE_KEY:", userAddr);
            } catch {
                // Fallback: use current private key
                address userAddr = vm.addr(privateKey);
                user = bytes32(uint256(uint160(userAddr)));
                console.log("User address derived from PRIVATE_KEY:", userAddr);
            }
        }

        // Get parameters
        uint64 subaccountId;
        try vm.envUint("SUBACCOUNT_ID") returns (uint256 envSubaccountId) {
            subaccountId = uint64(envSubaccountId);
        } catch {
            subaccountId = uint64(1000000009); // Default
        }

        uint256 collateralAmount;
        try vm.envUint("COLLATERAL_AMOUNT") returns (uint256 envAmount) {
            collateralAmount = envAmount;
        } catch {
            collateralAmount = 1000000000; // Default: 1000 USDC (6 decimals)
        }

        uint64 defaultCollateralCoinId = asset.defaultCollateralCoinId();
        if (defaultCollateralCoinId == 0) {
            console.log("ERROR: defaultCollateralCoinId is not set!");
            revert("DefaultCollateralCoinIdNotSet");
        }
        console.log("Default collateral coin ID:", defaultCollateralCoinId);

        // Check if we need to set up coin first
        (uint64 id, string memory symbol, uint32 stepSizeScale) = asset.coins(defaultCollateralCoinId);
        MarginAsset.Coin memory existingCoin = MarginAsset.Coin({
            id: id,
            symbol: symbol,
            stepSizeScale: stepSizeScale
        });
        bool needCoinUpdate = (existingCoin.id == 0);

        // Prepare batch update data
        Asset.BatchUpdateData memory batchData;

        // 1. Coin updates (if needed)
        if (needCoinUpdate) {
            console.log("Setting up coin information...");
            MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
            coinUpdates[0] = MarginAsset.Coin({
                id: defaultCollateralCoinId,
                symbol: "USDC",
                stepSizeScale: 6
            });
            batchData.coinUpdates = coinUpdates;
        } else {
            batchData.coinUpdates = new MarginAsset.Coin[](0);
            console.log("Coin already exists, skipping coin update");
        }

        // 2. Subaccount updates
        console.log("Setting up subaccount...");
        console.log("  Subaccount ID:", subaccountId);
        console.log("  User address (bytes32):", vm.toString(user));
        
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        subaccountUpdates[0] = MarginAsset.Subaccount({
            id: subaccountId,
            chainAddress: user,
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "",
            tradeSettings: tradeSettings
        });
        batchData.subaccountUpdates = subaccountUpdates;

        // 3. PerpetualAsset updates
        console.log("Setting up perpetual asset...");
        console.log("  Collateral amount:", collateralAmount);
        
        // Convert to int64 (ensure it fits)
        int64 crossCollateralAmount;
        if (collateralAmount > uint256(uint64(type(int64).max))) {
            crossCollateralAmount = type(int64).max;
            console.log("  WARNING: Amount too large, using max int64");
        } else {
            crossCollateralAmount = int64(int256(collateralAmount));
        }

        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](1);
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](0); // No positions for simple test
        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: subaccountId,
            collateralCoinId: defaultCollateralCoinId,
            crossCollateralAmount: crossCollateralAmount,
            positions: positions
        });
        batchData.perpetualAssetUpdates = perpetualAssetUpdates;

        // 4. Empty arrays for other updates
        batchData.exchangeUpdates = new MarginAsset.Exchange[](0);
        batchData.fundingIndexUpdates = new MarginAsset.FundingIndex[](0);
        batchData.oraclePriceUpdates = new MarginAsset.OraclePrice[](0);

        // Get current batch ID and increment
        uint256 currentBatchId = asset.lastBatchId();
        uint256 nextBatchId = currentBatchId + 1;
        int32 seqInBatch = 0;
        uint256 antxChainHeight = asset.lastAntxChainHeight() + 1;

        console.log("\n=== Batch Update Parameters ===");
        console.log("Batch ID:", nextBatchId);
        console.log("Sequence in batch:", seqInBatch);
        console.log("AntX chain height:", antxChainHeight);
        console.log("Subaccount ID:", subaccountId);
        console.log("Collateral amount:", collateralAmount);
        console.log("Cross collateral amount (int64):", uint256(uint64(crossCollateralAmount)));

        // Execute batch update
        console.log("\nExecuting batch update...");
        asset.batchUpdate(nextBatchId, seqInBatch, antxChainHeight, batchData);

        // Check available amount
        uint256 available = asset.availableAmountBySubAccountId(subaccountId);
        console.log("\n=== Setup Complete ===");
        console.log("Available amount for subaccount:", available);
        console.log("Last batch time:", asset.lastBatchTime());
        console.log("Force withdraw time lock:", asset.FORCE_WITHDRAW_TIME_LOCK());
        
        uint256 unlockTime = asset.lastBatchTime() + asset.FORCE_WITHDRAW_TIME_LOCK();
        console.log("Force withdraw unlock time:", unlockTime);
        console.log("Current time:", block.timestamp);
        
        if (block.timestamp >= unlockTime) {
            console.log("Force withdraw is available now!");
        } else {
            console.log("Force withdraw will be available at:", unlockTime);
            console.log("  Time remaining (seconds):", unlockTime - block.timestamp);
        }

        vm.stopBroadcast();
    }
}

