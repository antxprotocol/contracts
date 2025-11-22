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
        
        // StargateWithdraw contract address
        address stargateWithdrawAddress = vm.envAddress("STARGATE_WITHDRAW_ADDRESS");
        StargateWithdraw stargateWithdraw = StargateWithdraw(stargateWithdrawAddress);
        
        console.log("StargateWithdraw contract:", stargateWithdrawAddress);
        console.log("Current owner:", stargateWithdraw.owner());
        
        // LayerZero Endpoint IDs for different chains
        // Reference: https://layerzero.gitbook.io/docs/technical-reference/mainnet/supported-chain-ids
        // Common LayerZero Endpoint IDs:
        // Ethereum Mainnet: 30101
        // BNB Chain: 30102
        // Avalanche: 30106
        // Polygon: 30109
        // Arbitrum: 30110
        // Optimism: 30111
        // Fantom: 30112
        // Base: 30184
        // Arbitrum Sepolia: 40231
        
        // Configure chains - Uncomment the chains you want to support
        // LayerZero Endpoint IDs reference: https://layerzero.gitbook.io/docs/technical-reference/mainnet/supported-chain-ids
        
        // Example: Configure Ethereum Mainnet
        // uint256 ethereumChainId = 1;
        // uint32 ethereumEndpointId = 30101;
        // stargateWithdraw.setChainEndpoint(ethereumChainId, ethereumEndpointId);
        // stargateWithdraw.setChainSupport(ethereumChainId, true);
        // console.log("Configured Ethereum Mainnet");
        // console.log("  Chain ID:", ethereumChainId);
        // console.log("  Endpoint ID:", ethereumEndpointId);
        
        // Example: Configure Base
        // uint256 baseChainId = 8453;
        // uint32 baseEndpointId = 30184;
        // stargateWithdraw.setChainEndpoint(baseChainId, baseEndpointId);
        // stargateWithdraw.setChainSupport(baseChainId, true);
        // console.log("Configured Base");
        // console.log("  Chain ID:", baseChainId);
        // console.log("  Endpoint ID:", baseEndpointId);
        
        // Example: Configure Polygon
        // uint256 polygonChainId = 137;
        // uint32 polygonEndpointId = 30109;
        // stargateWithdraw.setChainEndpoint(polygonChainId, polygonEndpointId);
        // stargateWithdraw.setChainSupport(polygonChainId, true);
        // console.log("Configured Polygon");
        // console.log("  Chain ID:", polygonChainId);
        // console.log("  Endpoint ID:", polygonEndpointId);
        
        // Example: Configure BNB Chain
        // uint256 bnbChainId = 56;
        // uint32 bnbEndpointId = 30102;
        // stargateWithdraw.setChainEndpoint(bnbChainId, bnbEndpointId);
        // stargateWithdraw.setChainSupport(bnbChainId, true);
        // console.log("Configured BNB Chain");
        // console.log("  Chain ID:", bnbChainId);
        // console.log("  Endpoint ID:", bnbEndpointId);
        
        // Example: Configure Avalanche
        // uint256 avalancheChainId = 43114;
        // uint32 avalancheEndpointId = 30106;
        // stargateWithdraw.setChainEndpoint(avalancheChainId, avalancheEndpointId);
        // stargateWithdraw.setChainSupport(avalancheChainId, true);
        // console.log("Configured Avalanche");
        // console.log("  Chain ID:", avalancheChainId);
        // console.log("  Endpoint ID:", avalancheEndpointId);
        
        // Example: Configure Optimism
        // uint256 optimismChainId = 10;
        // uint32 optimismEndpointId = 30111;
        // stargateWithdraw.setChainEndpoint(optimismChainId, optimismEndpointId);
        // stargateWithdraw.setChainSupport(optimismChainId, true);
        // console.log("Configured Optimism");
        // console.log("  Chain ID:", optimismChainId);
        // console.log("  Endpoint ID:", optimismEndpointId);
        
        // Example: Configure Fantom
        // uint256 fantomChainId = 250;
        // uint32 fantomEndpointId = 30112;
        // stargateWithdraw.setChainEndpoint(fantomChainId, fantomEndpointId);
        // stargateWithdraw.setChainSupport(fantomChainId, true);
        // console.log("Configured Fantom");
        // console.log("  Chain ID:", fantomChainId);
        // console.log("  Endpoint ID:", fantomEndpointId);
        
        // You can configure multiple chains by uncommenting multiple sections above
        
        console.log("Configuration completed!");
        
        vm.stopBroadcast();
    }
}

