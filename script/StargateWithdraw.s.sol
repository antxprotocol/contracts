// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {StargateWithdraw} from "../src/stargate/StargateWithdraw.sol";

/**
 * @title StargateWithdrawScript
 * @dev Deployment script for StargateWithdraw contract
 */
contract StargateWithdrawScript is Script {
    function setUp() public {}
    
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying StargateWithdraw with account:", deployer);
        console.log("Account balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Configuration - Update these addresses based on your deployment network
        // USDC address
        // Arbitrum Sepolia: 0x3253a335E7bFfB4790Aa4C25C4250d206E9b9773
        // Arbitrum Mainnet: Check Stargate documentation
        address usdcAddress = vm.envOr("USDC_ADDRESS", address(0x3253a335E7bFfB4790Aa4C25C4250d206E9b9773));
        console.log("USDC address:", usdcAddress);
        
        // Stargate Pool address - Update based on your network
        // For Arbitrum Sepolia, check Stargate documentation for the correct pool address
        // Note: Stargate v2 pool addresses may vary by network
        address stargatePoolAddress = vm.envAddress("STARGATE_POOL_ADDRESS");
        console.log("Stargate Pool address:", stargatePoolAddress);
        
        // Owner address (can be deployer or a multisig)
        // If not set, use deployer as owner
        address owner = vm.envOr("OWNER_ADDRESS", deployer);
        console.log("Owner address:", owner);
        
        // Deploy StargateWithdraw contract
        StargateWithdraw stargateWithdraw = new StargateWithdraw(
            usdcAddress,
            stargatePoolAddress,
            owner
        );
        
        console.log("StargateWithdraw deployed at:", address(stargateWithdraw));
        console.log("USDC token:", address(stargateWithdraw.usdc()));
        console.log("Stargate Pool:", address(stargateWithdraw.stargatePool()));
        console.log("Owner:", stargateWithdraw.owner());
        
        vm.stopBroadcast();
    }
}

