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

    address payable oracleAddress = payable(0x2C122b77028B8c47587696a30E5359Ad95e5653c);
    address node1Address = 0xDEfaa510D5E6c1D9C41Aa1a268c4263265502DC8;
    address node2Address = 0xF68a530Cc3d134b6007062028feC1592273B31E1;
    
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Deploying Ed25519Oracle with account:", deployer);
        console.log("Account balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy oracle with default parameters
        Ed25519Oracle oracle = Ed25519Oracle(oracleAddress);
        console.log("Ed25519Oracle deployed at:", address(oracle));
        
        oracle.registerNode{value: 0.001 ether}(node1Address, 0.001 ether);
        oracle.registerNode{value: 0.001 ether}(node2Address, 0.001 ether);

        vm.stopBroadcast();
    }
}
