// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {MarginAssetCalculator} from "../src/margin/MarginAsset.sol";

/**
 * @title MarginAssetCalculatorScript
 * @dev Deployment script for MarginAssetCalculator contract
 */
contract MarginAssetCalculatorScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying MarginAssetCalculator with account:", deployer);
        console.log("Account balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy margin asset calculator with default parameters
        MarginAssetCalculator calculator = new MarginAssetCalculator();
        console.log("MarginAssetCalculator deployed at:", address(calculator));

        vm.stopBroadcast();
    }
}
