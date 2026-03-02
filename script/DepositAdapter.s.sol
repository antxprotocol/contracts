// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/DepositAdapter.sol";

contract DepositAdapterScript is Script {
    // BSC Mainnet
    address constant BSC_PANCAKE_ROUTER = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
    address constant BSC_PANCAKE_FACTORY = 0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73;
    address constant BSC_WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address usdcAddress;
        address assetProxyAddress;
        address pancakeRouter;
        address pancakeFactory;
        address wbnb;

        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            usdcAddress = vm.envAddress("DEVNET_USDC_ADDRESS");
            assetProxyAddress = vm.envAddress("DEVNET_ASSET_PROXY_ADDRESS");
            pancakeRouter = vm.envOr("DEVNET_PANCAKE_ROUTER", BSC_PANCAKE_ROUTER);
            pancakeFactory = vm.envOr("DEVNET_PANCAKE_FACTORY", BSC_PANCAKE_FACTORY);
            wbnb = vm.envOr("DEVNET_WBNB", BSC_WBNB);
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            usdcAddress = vm.envAddress("TESTNET_USDC_ADDRESS");
            assetProxyAddress = vm.envAddress("TESTNET_ASSET_PROXY_ADDRESS");
            pancakeRouter = vm.envOr("TESTNET_PANCAKE_ROUTER", BSC_PANCAKE_ROUTER);
            pancakeFactory = vm.envOr("TESTNET_PANCAKE_FACTORY", BSC_PANCAKE_FACTORY);
            wbnb = vm.envOr("TESTNET_WBNB", BSC_WBNB);
        } else {
            usdcAddress = vm.envAddress("MAINNET_USDC_ADDRESS");
            assetProxyAddress = vm.envAddress("MAINNET_ASSET_PROXY_ADDRESS");
            pancakeRouter = vm.envOr("MAINNET_PANCAKE_ROUTER", BSC_PANCAKE_ROUTER);
            pancakeFactory = vm.envOr("MAINNET_PANCAKE_FACTORY", BSC_PANCAKE_FACTORY);
            wbnb = vm.envOr("MAINNET_WBNB", BSC_WBNB);
        }

        console.log("USDC:", usdcAddress);
        console.log("Asset (proxy):", assetProxyAddress);
        console.log("PancakeSwap Router:", pancakeRouter);
        console.log("PancakeSwap Factory:", pancakeFactory);
        console.log("WBNB:", wbnb);

        DepositAdapter adapter = new DepositAdapter(
            usdcAddress,
            assetProxyAddress,
            pancakeRouter,
            pancakeFactory,
            wbnb
        );
        console.log("DepositAdapter deployed at:", address(adapter));

        vm.stopBroadcast();
    }
}
