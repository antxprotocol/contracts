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

        // Get proxy address from environment variable
        address proxyAddress = vm.envAddress("ASSET_PROXY_ADDRESS");
        console.log("Asset proxy address:", proxyAddress);
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
        // asset.setWithdrawOperator(withdrawOperator);

        // // set settlement operator
        // address settlementOperator = 0x99998e313c602C1D602e6874446b3eaAB4CD7bE2;
        // console.log("settlement operator address at:", address(settlementOperator));
        // asset.setSettlementAddress(settlementOperator);

        // settlementOperator = asset.settlementOperator();
        // console.log("settlement operator address at:", address(settlementOperator));

        //
        // address marginAsset = 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678;
        // console.log("Margin asset address at:", address(marginAsset));
        // asset.setMarginAsset(marginAsset);

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address stargateWithdrawAddress;
        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            stargateWithdrawAddress = vm.envAddress("DEVNET_STARGATE_WITHDRAW_ADDRESS");
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            stargateWithdrawAddress = vm.envAddress("TESTNET_STARGATE_WITHDRAW_ADDRESS");
        } else {
            stargateWithdrawAddress = vm.envAddress("MAINNET_STARGATE_WITHDRAW_ADDRESS");
        }
        console.log("Stargate withdraw address at:", address(stargateWithdrawAddress));
        asset.setStargateWithdraw(payable(stargateWithdrawAddress));

        vm.stopBroadcast();
    }
}
