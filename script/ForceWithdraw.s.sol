// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

/**
 * @title ForceWithdrawScript
 * @notice Script to execute force withdraw from Asset contract
 * @dev 
 * Usage:
 *   forge script script/ForceWithdraw.s.sol:ForceWithdrawScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast
 * 
 * Required environment variables:
 *   - FORCE_WITHDRAW_PRIVATE_KEY: Private key for signing transactions (must match user address in subaccount)
 *   - CURRENT_ENV: "devnet", "testnet", or "mainnet"
 *   - AMOUNT: Amount to withdraw (in wei, default: 1000000)
 * 
 * Note: 
 *   - The function uses msg.sender to get the user address, so the transaction must be sent from the user's address
 *   - Before running this script, you must first run SetupForceWithdraw.s.sol to set up:
 *     1. User subaccount with chainAddress matching the private key
 *     2. PerpetualAsset with sufficient collateral amount
 *     3. Wait for force withdraw time lock to pass
 * 
 * Example:
 *   export FORCE_WITHDRAW_PRIVATE_KEY=0x...
 *   export CURRENT_ENV=testnet
 *   export AMOUNT=1000000
 *   forge script script/ForceWithdraw.s.sol:ForceWithdrawScript --rpc-url <RPC_URL> --broadcast
 */

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";

contract ForceWithdrawScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("FORCE_WITHDRAW_PRIVATE_KEY");
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

        // Get parameters from environment variables
        uint64 subaccountId; // Will be set from addressToSubaccountId mapping
        uint256 amount = 1000000;
        uint64 dstChainId = uint64(block.chainid);

        // Get user address from private key (msg.sender will be this address)
        // The subaccount should have been set up with this address via SetupForceWithdraw.s.sol
        address userAddr = vm.addr(privateKey);
        bytes32 user = bytes32(uint256(uint160(userAddr)));
        console.log("User address (msg.sender):", userAddr);
        
        // Verify user has a subaccount by checking addressToSubaccountId mapping
        uint64 userSubaccountId = asset.addressToSubaccountId(user);
        if (userSubaccountId == 0) {
            console.log("ERROR: User does not have a subaccount!");
            console.log("Please run SetupForceWithdraw.s.sol first to set up the subaccount.");
            revert("SubaccountNotFound");
        }
        
        // Use the subaccountId from the mapping (may differ from env variable)
        subaccountId = userSubaccountId;
        console.log("Subaccount ID (from mapping):", subaccountId);
        
        // Verify subaccount exists by checking available amount
        try asset.availableAmountBySubAccountId(subaccountId) returns (uint256) {
            console.log("Subaccount verified - exists and has data");
        } catch {
            console.log("ERROR: Subaccount not found or not properly set up!");
            console.log("Please run SetupForceWithdraw.s.sol first to set up the subaccount.");
            revert("SubaccountNotFound");
        }

        // Check if time lock has passed
        uint256 lastBatchTime = asset.lastBatchTime();
        // FORCE_WITHDRAW_TIME_LOCK is 7 days (or 7 minutes for test)
        uint256 forceWithdrawTimeLock = 7 minutes;
        uint256 unlockTime = lastBatchTime + forceWithdrawTimeLock;
        
        console.log("Last batch time:", lastBatchTime);
        console.log("Force withdraw time lock:", forceWithdrawTimeLock);
        console.log("Unlock time:", unlockTime);
        console.log("Current time:", block.timestamp);
        
        if (block.timestamp < unlockTime) {
            console.log("ERROR: Time lock not passed yet!");
            console.log("Need to wait until:", unlockTime);
            console.log("Time remaining (seconds):", unlockTime - block.timestamp);
            revert("TimeLockNotPassed");
        }

        // Check available amount
        uint256 available = asset.availableAmountBySubAccountId(subaccountId);
        console.log("Available amount for subaccount:", available);
        console.log("Requested amount:", amount);
        
        if (available < amount) {
            console.log("ERROR: Insufficient available balance!");
            console.log("Available:", available);
            console.log("Requested:", amount);
            revert("InsufficientBalance");
        }

        // Log parameters
        console.log("=== Force Withdraw Parameters ===");
        console.log("User address (msg.sender):", userAddr);
        console.log("Subaccount ID:", subaccountId);
        console.log("Amount:", amount);
        console.log("Destination Chain ID:", dstChainId);

        // Execute force withdraw
        // Note: forceWithdraw uses msg.sender to get user address, so the transaction
        // must be sent from the user's address (which is derived from privateKey)
        console.log("\nExecuting force withdraw...");
        asset.forceWithdraw(amount, dstChainId);

        console.log("Force withdraw executed successfully!");
        console.log("Transaction hash:", vm.toString(tx.origin));

        vm.stopBroadcast();
    }
}

