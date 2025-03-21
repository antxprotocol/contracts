// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "../src/AntStrargateAdapterImpl.sol";

// Deploys OFT adapter to Sepolia
contract AntStrargateAdapterARBScript is Script {
    address constant USDC_STARGATE_ENDPOINT = 0x543BdA7c6cA4384FE90B1F5929bb851F52888983;
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        // Deploy
        new AntStrargateAdapterImpl(
            USDC_STARGATE_ENDPOINT
        );

        vm.stopBroadcast();
    }
}