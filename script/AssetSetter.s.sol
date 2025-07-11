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

        address assetDeployedAddress = 0xF58950B4263B13D18B558360A4089A47BC00696D;
        console.log("Asset address at:", address(assetDeployedAddress));

        Asset asset  = Asset(assetDeployedAddress);

        // address settlementOperator = asset.settlementOperator();
        // console.log("settlement operator address at:", address(settlementOperator));

        // address systemAddress = asset.systemAddress();
        // console.log("system address at:", address(systemAddress));

        address withdrawOperator = asset.withdrawOperator();
        console.log("withdraw operator address at:", address(withdrawOperator));


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

        vm.stopBroadcast();
    }
}