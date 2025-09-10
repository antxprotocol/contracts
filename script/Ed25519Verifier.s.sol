// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/verify/Ed25519SignatureValidation.sol";

contract Ed25519VerifierScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        // Deploy Ed25519Verifier
        Ed25519SignatureValidation ed25519Verifier =  new Ed25519SignatureValidation(vm.addr(privateKey));
        console.log("SignatureValidation deployed at:", address(ed25519Verifier));

        vm.stopBroadcast();
    }
}