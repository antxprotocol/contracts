// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {StargateWithdraw} from "../src/stargate/StargateWithdraw.sol";

/**
 * @title StargateWithdrawSetterScript
 * @dev Configuration script for StargateWithdraw contract
 * @notice This script configures chain endpoints and enables supported chains
 */
contract StargateWithdrawSetterScript is Script {
    function setUp() public {}
    
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console.log("Configuring StargateWithdraw with account:", deployer);
        
        vm.startBroadcast(deployerPrivateKey);
        

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address stargateWithdrawAddress;
        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            stargateWithdrawAddress = vm.envAddress("DEVNET_STARGATE_WITHDRAW_ADDRESS");
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            stargateWithdrawAddress = vm.envAddress("TESTNET_STARGATE_WITHDRAW_ADDRESS");
        } else {
            stargateWithdrawAddress = vm.envAddress("MAINNET_STARGATE_WITHDRAW_ADDRESS");
        }
        StargateWithdraw stargateWithdraw = StargateWithdraw(stargateWithdrawAddress);
        
        console.log("StargateWithdraw contract:", stargateWithdrawAddress);
        console.log("Current owner:", stargateWithdraw.owner());

        // https://docs.layerzero.network/v1/deployments/deployed-contracts?stages=testnet&chains=sepolia
        uint256 sepoliaChainId = 11155111;
        uint32 sepoliaEndpointId = 10161;
        stargateWithdraw.setChainEndpoint(sepoliaChainId, sepoliaEndpointId);
        stargateWithdraw.setChainSupport(sepoliaChainId, true);
        
        console.log("Configuration completed!");
        vm.stopBroadcast();
    }
}

