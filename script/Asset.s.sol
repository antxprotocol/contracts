// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";

contract AssetScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        address usdcAddress;

        address[] memory signers = new address[](3);
        signers[0] = 0x4626eb76a7c2896645B0117614Ec0555e6E3a180;
        signers[1] = 0x6c7459c4B3B84E24734E59D4a6749EB02Ea26406;
        signers[2] = 0x3171E2318402Cea35849CDaed28261A25e25849c;

        string memory currentEnv = vm.envString("CURRENT_ENV");
        // address settlementOperator = 0x99998e313c602C1D602e6874446b3eaAB4CD7bE2; // devnet
        address settlementOperator;
        address withdrawOperator;
        address ed25519Oracle;
        address marginAssetCalculator;
        address stargateWithdraw ;

        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            usdcAddress = vm.envAddress("DEVNET_USDC_ADDRESS"); // devnet
            settlementOperator = vm.envAddress("DEVNET_SETTLEMENT_ADDRESS"); // devnet
            withdrawOperator = vm.envAddress("DEVNET_WITHDRAW_ADDRESS"); // devnet
            ed25519Oracle = vm.envAddress("DEVNET_ED25519_ORACLE_ADDRESS"); // devnet
            marginAssetCalculator = vm.envAddress("DEVNET_MARGIN_ASSET_CALCULATOR_ADDRESS"); // devnet
            stargateWithdraw = vm.envAddress("DEVNET_STARGATE_WITHDRAW_ADDRESS"); // devnet
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            usdcAddress = vm.envAddress("TESTNET_USDC_ADDRESS"); // testnet
            settlementOperator = vm.envAddress("TESTNET_SETTLEMENT_ADDRESS"); // testnet
            withdrawOperator = vm.envAddress("TESTNET_WITHDRAW_ADDRESS"); // testnet
            ed25519Oracle = vm.envAddress("TESTNET_ED25519_ORACLE_ADDRESS"); // testnet
            marginAssetCalculator = vm.envAddress("TESTNET_MARGIN_ASSET_CALCULATOR_ADDRESS"); // testnet
            stargateWithdraw = vm.envAddress("TESTNET_STARGATE_WITHDRAW_ADDRESS"); // testnet
        } else {
            usdcAddress = vm.envAddress("MAINNET_USDC_ADDRESS"); // mainnet
            settlementOperator = vm.envAddress("MAINNET_SETTLEMENT_ADDRESS"); // mainnet
            withdrawOperator = vm.envAddress("MAINNET_WITHDRAW_ADDRESS"); // mainnet
            ed25519Oracle = vm.envAddress("MAINNET_ED25519_ORACLE_ADDRESS"); // mainnet
            marginAssetCalculator = vm.envAddress("MAINNET_MARGIN_ASSET_CALCULATOR_ADDRESS"); // mainnet
            stargateWithdraw = vm.envAddress("MAINNET_STARGATE_WITHDRAW_ADDRESS"); // mainnet
        }
        console.log("USDC address at:", address(usdcAddress));
        console.log("Settlement address at:", address(settlementOperator));
        console.log("Withdraw operator address at:", address(withdrawOperator));
        console.log("Ed25519 oracle address at:", address(ed25519Oracle));
        console.log("Margin asset calculator address at:", address(marginAssetCalculator));
        console.log("Stargate withdraw address at:", address(stargateWithdraw));

        // Deploy asset
        Asset asset =  new Asset(address(usdcAddress));
        console.log("Asset deployed at:", address(asset));

        // set signers
        asset.setSigners(signers);

        // set settlement operator
        asset.setSettlementAddress(settlementOperator);

        // set withdraw operator
        asset.setWithdrawOperator(withdrawOperator);

        // set ed25519 oracle
        asset.setEd25519Oracle(ed25519Oracle);

        // set margin asset
        asset.setMarginAsset(marginAssetCalculator);

        // set stargate withdraw
        asset.setStargateWithdraw(stargateWithdraw);

        vm.stopBroadcast();
    }
}