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
        StargateWithdraw stargateWithdraw = StargateWithdraw(payable(stargateWithdrawAddress));
        
        console.log("StargateWithdraw contract:", stargateWithdrawAddress);
        console.log("Current owner:", stargateWithdraw.owner());

        // https://stargateprotocol.gitbook.io/stargate/v2-developer-docs/technical-reference/testnet-contracts
        uint256 arbitrumSepoliaChainId = 421614;
        uint32 arbitrumSepoliaEndpointId = 40231;
        stargateWithdraw.setChainEndpoint(arbitrumSepoliaChainId, arbitrumSepoliaEndpointId);
        stargateWithdraw.setChainSupport(arbitrumSepoliaChainId, true);
        
        console.log("Configuration completed!");
        vm.stopBroadcast();
    }
}

