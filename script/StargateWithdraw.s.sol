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

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address usdcAddress;
        address stargatePoolAddress;
        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            usdcAddress = vm.envAddress("DEVNET_USDC_ADDRESS");
            stargatePoolAddress = vm.envAddress("DEVNET_STARGATE_POOL_USDC_ADDRESS");
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            usdcAddress = vm.envAddress("TESTNET_USDC_ADDRESS");
            stargatePoolAddress = vm.envAddress("TESTNET_STARGATE_POOL_USDC_ADDRESS");
        } else {
            usdcAddress = vm.envAddress("MAINNET_USDC_ADDRESS");
            stargatePoolAddress = vm.envAddress("MAINNET_STARGATE_POOL_USDC_ADDRESS");
        }
        console.log("USDC address:", usdcAddress);

        // Stargate Pool address - Update based on your network
        console.log("Stargate Pool address:", stargatePoolAddress);

        // Deploy StargateWithdraw contract
        StargateWithdraw stargateWithdraw = new StargateWithdraw(usdcAddress, stargatePoolAddress, deployer);

        console.log("StargateWithdraw deployed at:", address(stargateWithdraw));
        console.log("USDC token:", address(stargateWithdraw.USDC()));
        console.log("Stargate Pool:", address(stargateWithdraw.stargate()));
        console.log("Owner:", stargateWithdraw.owner());

        vm.stopBroadcast();
    }
}

