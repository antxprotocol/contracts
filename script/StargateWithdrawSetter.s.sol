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
        address assetContractAddress;
        if (keccak256(bytes(currentEnv)) == keccak256(bytes("devnet"))) {
            stargateWithdrawAddress = vm.envAddress("DEVNET_STARGATE_WITHDRAW_ADDRESS");
            assetContractAddress = vm.envAddress("DEVNET_ASSET_PROXY_ADDRESS");
        } else if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            stargateWithdrawAddress = vm.envAddress("TESTNET_STARGATE_WITHDRAW_ADDRESS");
            assetContractAddress = vm.envAddress("TESTNET_ASSET_PROXY_ADDRESS");
        } else {
            stargateWithdrawAddress = vm.envAddress("MAINNET_STARGATE_WITHDRAW_ADDRESS");
            assetContractAddress = vm.envAddress("MAINNET_ASSET_PROXY_ADDRESS");
        }
        StargateWithdraw stargateWithdraw = StargateWithdraw(payable(stargateWithdrawAddress));

        console.log("StargateWithdraw contract:", stargateWithdrawAddress);
        console.log("Current owner:", stargateWithdraw.owner());

        // https://stargateprotocol.gitbook.io/stargate/v2-developer-docs/technical-reference/testnet-contracts
        // uint256 arbitrumSepoliaChainId = 421614;
        // uint32 arbitrumSepoliaEndpointId = 40231;


        uint256 arbitrumChainId = 42161;
        uint32 arbitrumEndpointId = 30110;
        stargateWithdraw.setChainEndpoint(arbitrumChainId, arbitrumEndpointId);
        stargateWithdraw.setChainSupport(arbitrumChainId, true);


        uint256 baseChainId = 8453;
        uint32 baseEndpointId = 30184;
        stargateWithdraw.setChainEndpoint(baseChainId, baseEndpointId);
        stargateWithdraw.setChainSupport(baseChainId, true);

        // stargateWithdraw.setAssetContract(assetContractAddress);

        console.log("Configuration completed!");
        vm.stopBroadcast();
    }
}

