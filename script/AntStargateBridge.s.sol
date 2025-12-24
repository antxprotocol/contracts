pragma solidity ^0.8.28;

import "@forge-std/Script.sol";

import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../src/stargate/AntStrargateAdapter.sol";

// Bridge tokens from Sepolia to BscChain
contract AntStargateBridgeScript is Script {
    address constant ARB_SEPOLIA_ADAPTER_ADDRESS = 0xE348621f6fd4031e2b5A2E2f03c2F6140e50A9A2; // arb sepolia adapter address
    address constant USDC_TOKEN = 0x3253a335E7bFfB4790Aa4C25C4250d206E9b9773; // arb sepolia usdc address
    address constant USDC_STARGATE_ENDPOINT = 0x543BdA7c6cA4384FE90B1F5929bb851F52888983; // arb sepolia stargate endpoint
    address constant receiver = 0x2E8D9A9bF85A06C57f46bA7Ac8e0c25259c544cC; // sepolia receiver address
    uint32 constant destinationEndpointId = 40161; // sepolia testnet

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        address signer = vm.addr(privateKey);

        // Define the send parameters
        uint256 tokensToSend = 1000000; // 1 $USDC tokens

        // Get the Adapter contract instance
        AntStrargateAdapter arbSepoliaAdapter = new AntStrargateAdapter(ARB_SEPOLIA_ADAPTER_ADDRESS);
        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            arbSepoliaAdapter.prepareTakeTaxi(destinationEndpointId, tokensToSend, receiver);

        // Quote the send fee
        MessagingFee memory fee = arbSepoliaAdapter.quoteSend(sendParam, false);
        console.log("Native fee: %d", fee.nativeFee);

        // Approve the OFT contract to spend USDC tokens
        IERC20(USDC_TOKEN).approve(USDC_STARGATE_ENDPOINT, tokensToSend);

        IStargate stargate = IStargate(USDC_STARGATE_ENDPOINT);
        stargate.sendToken{value: valueToSend}(sendParam, messagingFee, signer);
        console.log("Tokens bridged successfully!");
    }
}
