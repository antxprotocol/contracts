pragma solidity ^0.8.28;

import "@forge-std/Script.sol";

import {IOFT,MessagingFee, OFTReceipt, SendParam } from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../src/strargate/AntStrargateAdapter.sol";
import "../src/strargate/AntStrargateAdapterImpl.sol";

// Bridge tokens from Sepolia to BscChain
contract SendOFTScript is Script {
    address constant USDC_TOKEN = 0x2F6F07CDcf3588944Bf4C42aC74ff24bF56e7590;
    address constant USDC_STARGATE_ENDPOINT = 0x4985b8fcEA3659FD801a5b857dA1D00e985863F0;
    address constant receiver = 0xF6d79F80758029D8957ee4028Fc0156ebEb3b751;
    uint32 constant destinationEndpointId = 40231;  // ARB testnet

    function run() external {
        address SEPOLIA_ADAPTER_ADDRESS = vm.envAddress(
            "SEPOLIA_ADAPTER_ADDRESS"
        );
        // address ARBCHAIN_ADAPTER_ADDRESS = vm.envAddress(
        //     "ARBCHAIN_ADAPTER_ADDRESS"
        // );

        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        address signer = vm.addr(privateKey);

        // Get the Adapter contract instance
        AntStrargateAdapterImpl sepoliaAdapter = new AntStrargateAdapterImpl(SEPOLIA_ADAPTER_ADDRESS);

        // Hook up Sepolia Adapter to BaseChain's OFT
       
        // Define the send parameters
        uint256 tokensToSend = 1000000; // 1 $USDC tokens

        // bytes memory options = OptionsBuilder
        //     .newOptions()
        //     .addExecutorLzReceiveOption(200000, 0);

        // SendParam memory sendParam = SendParam(
        //     ARBCHAIN_ENPOINT_ID,
        //     bytes32(uint256(uint160(signer))),
        //     tokensToSend,
        //     tokensToSend,
        //     options,
        //     "",
        //     ""
        // );

        // // Quote the send fee
        // MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        // console.log("Native fee: %d", fee.nativeFee);

        // Approve the OFT contract to spend USDC tokens
        IERC20(USDC_TOKEN).approve(
            USDC_STARGATE_ENDPOINT,
            tokensToSend
        );

       (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
        sepoliaAdapter.prepareTakeTaxi(destinationEndpointId, tokensToSend, receiver);

        IStargate stargate = IStargate(USDC_STARGATE_ENDPOINT);

        // stargate.setPeer(
        //     destinationEndpointId,
        //     bytes32(uint256(uint160(ARBCHAIN_ADAPTER_ADDRESS)))
        // );

        stargate.sendToken{ value: valueToSend }(sendParam, messagingFee, signer);
        console.log("Tokens bridged successfully!");
    }
}