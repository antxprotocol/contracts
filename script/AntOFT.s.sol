// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "../src/AntOFT.sol";

// Deploys OFT adapter to Sepolia
contract AntOFTScript is Script {
    address public constant LAYERZERO_ENDPOINT = 0x6EDCE65403992e310A62460808c4b910D972f10f;

    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        // Deploy
        new AntOFT(
            "AntOFT",
            "ANT",
            LAYERZERO_ENDPOINT,
            vm.addr(privateKey) // Wallet address of signer
        );

        vm.stopBroadcast();
    }
}