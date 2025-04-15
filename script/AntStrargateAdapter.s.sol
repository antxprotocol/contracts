// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "../src/strargate/AntStrargateAdapterImpl.sol";

// Deploys OFT adapter to Sepolia
contract AntStrargateAdapterScript is Script {
    address constant USDC_STARGATE_ENDPOINT = 0x4985b8fcEA3659FD801a5b857dA1D00e985863F0;
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