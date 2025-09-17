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

        address usdcAddress = 0x3253a335E7bFfB4790Aa4C25C4250d206E9b9773;
        console.log("USDC address at:", address(usdcAddress));

        address[] memory signers = new address[](3);
        signers[0] = 0x4626eb76a7c2896645B0117614Ec0555e6E3a180;
        signers[1] = 0x6c7459c4B3B84E24734E59D4a6749EB02Ea26406;
        signers[2] = 0x3171E2318402Cea35849CDaed28261A25e25849c;


        address systemAddress = 0x4626eb76a7c2896645B0117614Ec0555e6E3a180;
        console.log("System address at:", address(systemAddress));

        address settlementOperator = 0x99998e313c602C1D602e6874446b3eaAB4CD7bE2;
        console.log("Settlement address at:", address(settlementOperator));

        address withdrawOperator = 0x99998e313c602C1D602e6874446b3eaAB4CD7bE2;
        console.log("Withdraw operator address at:", address(withdrawOperator));

        // Deploy asset
        Asset asset =  new Asset(
            address(usdcAddress),
            signers,
            systemAddress,
            settlementOperator,
            withdrawOperator,
            address(0) // ed25519Oracle address (placeholder)
        );
        console.log("Asset deployed at:", address(asset));

        vm.stopBroadcast();
    }
}