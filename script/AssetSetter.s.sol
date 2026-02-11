// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";

contract AssetSetterScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address proxyAddress;
        address stargateWithdrawAddress;
        address settlementOperator;
        address withdrawOperator;
        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            proxyAddress = vm.envAddress("DEVNET_ASSET_PROXY_ADDRESS");
            stargateWithdrawAddress = vm.envAddress("DEVNET_STARGATE_WITHDRAW_ADDRESS");
            withdrawOperator = vm.envAddress("DEVNET_WITHDRAW_ADDRESS");
            settlementOperator = vm.envAddress("DEVNET_SETTLEMENT_ADDRESS");
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            proxyAddress = vm.envAddress("TESTNET_ASSET_PROXY_ADDRESS");
            stargateWithdrawAddress = vm.envAddress("TESTNET_STARGATE_WITHDRAW_ADDRESS");
            withdrawOperator = vm.envAddress("TESTNET_WITHDRAW_ADDRESS");
            settlementOperator = vm.envAddress("TESTNET_SETTLEMENT_ADDRESS");
        } else {
            proxyAddress = vm.envAddress("MAINNET_ASSET_PROXY_ADDRESS");
            stargateWithdrawAddress = vm.envAddress("MAINNET_STARGATE_WITHDRAW_ADDRESS");
            withdrawOperator = vm.envAddress("MAINNET_WITHDRAW_ADDRESS");
            settlementOperator = vm.envAddress("MAINNET_SETTLEMENT_ADDRESS");
        }
        console.log("Asset proxy address at:", address(proxyAddress));
        Asset asset = Asset(payable(proxyAddress));

        // address settlementOperator = asset.settlementOperator();
        // console.log("settlement operator address at:", address(settlementOperator));

        // address systemAddress = asset.systemAddress();
        // console.log("system address at:", address(systemAddress));

        // address withdrawOperator = asset.withdrawOperator();
        // console.log("withdraw operator address at:", address(withdrawOperator));

        // // set withdraw operator
        // address withdrawOperator = 0x99998e313c602C1D602e6874446b3eaAB4CD7bE2;
        // console.log("Withdraw operator address at:", address(withdrawOperator));
        asset.setWithdrawOperator(withdrawOperator);
        address currentWithdrawOperator = asset.withdrawOperator();
        console.log("withdraw operator address at:", address(currentWithdrawOperator));

        // // set settlement operator
        // address settlementOperator = 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678;
        // console.log("settlement operator address at:", address(settlementOperator));
        asset.setSettlementAddress(settlementOperator);
        address currentSettlementOperator = asset.settlementOperator();
        console.log("settlement operator address at:", address(currentSettlementOperator));

        // //
        // address marginAsset = 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678;
        // console.log("Margin asset address at:", address(marginAsset));
        // asset.setMarginAsset(marginAsset);

        // console.log("Stargate withdraw address at:", address(stargateWithdrawAddress));
        // asset.setStargateWithdraw(payable(stargateWithdrawAddress));

        vm.stopBroadcast();
    }
}
