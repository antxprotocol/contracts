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

        address assetDeployedAddress = 0x4ee398227391f1e7ddfd6D73056e7532dDe0e29a;
        console.log("Asset address at:", address(assetDeployedAddress));

        Asset asset  = Asset(payable(assetDeployedAddress));

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

        address stargateWithdraw = 0x0000000000000000000000000000000000000000;
        console.log("Stargate withdraw address at:", address(stargateWithdraw));
        asset.setStargateWithdraw(stargateWithdraw);

        vm.stopBroadcast();
    }
}