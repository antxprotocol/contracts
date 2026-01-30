// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";

contract AssetTransferOwnerScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address proxyAddress;
        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            proxyAddress = vm.envAddress("DEVNET_ASSET_PROXY_ADDRESS");
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            proxyAddress = vm.envAddress("TESTNET_ASSET_PROXY_ADDRESS");
        } else {
            proxyAddress = vm.envAddress("MAINNET_ASSET_PROXY_ADDRESS");
        }
        console.log("Asset proxy address at:", address(proxyAddress));
        Asset asset = Asset(payable(proxyAddress));

        address currentOwner = asset.owner();
        console.log("Current owner address before transfer at:", address(currentOwner));

        address newOwner = vm.envAddress("NEW_ASSET_SAFE_OWNER");
        console.log("New owner address:", address(newOwner));
        
        asset.transferOwnership(newOwner);
        currentOwner = asset.owner();
        console.log("Current owner address after transfer at:", address(currentOwner));

        vm.stopBroadcast();
    }
}
