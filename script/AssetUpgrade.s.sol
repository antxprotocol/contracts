// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

/**
 * @title AssetUpgradeScript
 * @notice Script to upgrade the Asset contract implementation via UUPS proxy
 * @dev This script:
 * 1. Deploys a new Asset implementation contract
 * 2. Upgrades the existing proxy to point to the new implementation
 * 3. Verifies the upgrade was successful
 *
 * Usage:
 * 1. Set environment variables:
 *    - PRIVATE_KEY: Private key of the owner account
 *    - ASSET_PROXY_ADDRESS: Address of the deployed Asset proxy contract
 *
 * 2. Run the script:
 *    forge script script/AssetUpgrade.s.sol:AssetUpgradeScript --rpc-url <RPC_URL> --broadcast --verify
 *
 * 3. For simulation (dry-run):
 *    forge script script/AssetUpgrade.s.sol:AssetUpgradeScript --rpc-url <RPC_URL>
 *
 * Important Notes:
 * - Only the owner of the Asset contract can execute upgrades
 * - The new implementation must be compatible with the existing storage layout
 * - Consider using upgradeToAndCall with migration data if you need to initialize new state variables
 */

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";

contract AssetUpgradeScript is Script {
    // ERC1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
    bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        console.log("Private key address:", vm.addr(privateKey));

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

        // Get current implementation address from storage slot
        address currentImplementation = _getImplementation(proxyAddress);
        console.log("Current implementation address:", currentImplementation);

        // Deploy new implementation contract
        Asset newImplementation = new Asset();
        console.log("New Asset implementation deployed at:", address(newImplementation));

        // Get Asset instance through proxy
        Asset asset = Asset(payable(proxyAddress));

        // Verify we are the owner (required for upgrade)
        address owner = asset.owner();
        console.log("Asset owner:", owner);
        // require(owner == msg.sender, "Only owner can upgrade");

        // Upgrade the proxy to new implementation
        // Option 1: Simple upgrade without additional call
        bytes memory upgradeData = "";
        // address newImplementation = 0x23D8eeb85b86f4Df893ef25AE041d1C095d9b10E;
        asset.upgradeToAndCall(address(newImplementation), upgradeData);
        console.log("Upgrade completed successfully!");

        // Verify the upgrade
        address newImplementationAddress = _getImplementation(proxyAddress);
        console.log("New implementation address:", newImplementationAddress);
        require(newImplementationAddress == address(newImplementation), "Upgrade verification failed");

        vm.stopBroadcast();
    }

    /**
     * @dev Read implementation address from ERC1967 storage slot
     */
    function _getImplementation(address proxy) internal view returns (address implementation) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        bytes32 value = vm.load(proxy, slot);
        implementation = address(uint160(uint256(value)));
    }
}

