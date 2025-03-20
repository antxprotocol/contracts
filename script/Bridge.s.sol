pragma solidity ^0.8.22;

import "@forge-std/Script.sol";
import {IOFT, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {IOAppCore} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/interfaces/IOAppCore.sol";
import {MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFTCore.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IAdapter is IOAppCore, IOFT {}

// Bridge tokens from Sepolia to BaseChain
contract SendOFTScript is Script {
    using OptionsBuilder for bytes;

    uint32 constant ARBCHAIN_ENPOINT_ID = 40231;
    address constant SEPOLIA_LINK_ADDRESS =
        0x779877A7B0D9E8603169DdbD7836e478b4624789;

    function run() external {
        address SEPOLIA_ADAPTER_ADDRESS = vm.envAddress(
            "SEPOLIA_ADAPTER_ADDRESS"
        );
        address ARBCHAIN_OFT_ADDRESS = vm.envAddress("ARBCHAIN_OFT_ADDRESS");

        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        address signer = vm.addr(privateKey);

        // Get the Adapter contract instance
        IAdapter sepoliaAdapter = IAdapter(SEPOLIA_ADAPTER_ADDRESS);

        // Hook up Sepolia Adapter to BaseChain's OFT
        sepoliaAdapter.setPeer(
            ARBCHAIN_ENPOINT_ID,
            bytes32(uint256(uint160(ARBCHAIN_OFT_ADDRESS)))
        );

        // Define the send parameters
        uint256 tokensToSend = 0.0001 ether; // 0.0001 $UNI tokens

        bytes memory options = OptionsBuilder
            .newOptions()
            .addExecutorLzReceiveOption(200000, 0);

        SendParam memory sendParam = SendParam(
            ARBCHAIN_ENPOINT_ID,
            bytes32(uint256(uint160(signer))),
            tokensToSend,
            tokensToSend,
            options,
            "",
            ""
        );

        // Quote the send fee
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        console.log("Native fee: %d", fee.nativeFee);

        // Approve the OFT contract to spend UNI tokens
        IERC20(SEPOLIA_LINK_ADDRESS).approve(
            SEPOLIA_ADAPTER_ADDRESS,
            tokensToSend
        );

        // Send the tokens
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, signer);

        console.log("Tokens bridged successfully!");
    }
}