// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Ed25519Oracle} from "../src/oracle/Ed25519Oracle.sol";

/**
 * @title Ed25519OracleScript
 * @dev Deployment script for Ed25519Oracle contract
 */
contract Ed25519OracleScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying Ed25519Oracle with account:", deployer);
        console.log("Account balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy oracle with default parameters
        Ed25519Oracle oracle = new Ed25519Oracle(
            0.001 ether, // minimumStake: 1 ETH
            5000, // consensusThreshold: 50%
            300, // consensusTimeout: 5 minutes
            3600 * 24 // maxDataAge: 1 day
        );

        console.log("Ed25519Oracle deployed at:", address(oracle));

        // Get initial stats
        (
            uint256 totalNodes,
            uint256 totalStakeAmount,
            uint256 minStake,
            uint256 consensusThresh,
            uint256 consensusTime,
            uint256 maxAge
        ) = oracle.getOracleStats();

        console.log("Oracle Stats:");
        console.log("  Total Nodes:", totalNodes);
        console.log("  Total Stake:", totalStakeAmount);
        console.log("  Min Stake:", minStake);
        console.log("  Consensus Threshold:", consensusThresh);
        console.log("  Consensus Timeout:", consensusTime);
        console.log("  Max Data Age:", maxAge);

        vm.stopBroadcast();
    }
}
