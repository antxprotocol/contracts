// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Ed25519Oracle} from "../src/oracle/Ed25519Oracle.sol";

/**
 * @title Ed25519OracleSetterScript
 * @dev Deployment script for Ed25519Oracle contract
 */
contract Ed25519OracleSetterScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        address oracleAddress;
        string memory currentEnv = vm.envString("CURRENT_ENV");
        address node1Address;
        address node2Address;

        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            oracleAddress = vm.envAddress("DEVNET_ED25519_ORACLE_ADDRESS");
            node1Address = 0xDEfaa510D5E6c1D9C41Aa1a268c4263265502DC8;
            node2Address = 0xF68a530Cc3d134b6007062028feC1592273B31E1;
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            oracleAddress = vm.envAddress("TESTNET_ED25519_ORACLE_ADDRESS");
            node1Address = 0x4b971aE314964A31Bda6f370f03567AC5E9b963a;
            node2Address = 0x0BF12419d6354ba13452D00C47d376f881EF7b5e;
        } else {
            oracleAddress = vm.envAddress("MAINNET_ED25519_ORACLE_ADDRESS");
            node1Address = 0x0000000000000000000000000000000000000000;
            node2Address = 0x0000000000000000000000000000000000000000;
        }

        console.log("Deploying Ed25519Oracle with account:", deployer);
        console.log("Account balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy oracle with default parameters
        Ed25519Oracle oracle = Ed25519Oracle(payable(oracleAddress));
        console.log("Ed25519Oracle deployed at:", address(oracle));

        oracle.registerNode{value: 0.001 ether}(node1Address, 0.001 ether);
        oracle.registerNode{value: 0.001 ether}(node2Address, 0.001 ether);

        // oracle.unregisterNode(node1AddressDev);
        // oracle.unregisterNode(node2AddressDev);

        vm.stopBroadcast();
    }
}
