// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/interfaces/ISettlement.sol";
import "../src/interfaces/IAsset.sol";
import {CompleteMerkle} from "@murky/CompleteMerkle.sol";

contract SettlementScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        address signer = vm.addr(privateKey);


        address assetAddress = 0x55Ca8edc95fB3c55587A9a15dd6e76eB31945CF6;
        console.log("Asset address at:", address(assetAddress));
        IAsset asset = IAsset(assetAddress);

        address settlementAddress = 0x51c8287803C4067A7851aE20425Fa226CB907aad;
        console.log("Settle address at:", address(settlementAddress));
        ISettlement settlement = ISettlement(settlementAddress);

       

        // Create items for each settlement type
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](2);
        
        items[0] = ISettlement.SettlementItem({
            orderId: 1101,
            businessOrderId: 1101,
            user: signer,
            amount: 10000000000000,
            types: ISettlement.SettlementType.TradeFeeIn
        });

        items[1] = ISettlement.SettlementItem({
            orderId: 1102,
            businessOrderId: 1102,
            user: signer,
            amount: 1000000,
            types: ISettlement.SettlementType.Deposit
        });

        // Generate batch
        uint256 batchId = 3;
        uint256 startBlock = 31;
        uint256 endBlock = 40;
        
        bytes32[] memory leaves = new bytes32[](items.length);
        for (uint256 i = 0; i < items.length; i++) {
            leaves[i] = settlement.generateLeaf(batchId, items[i]);
        }


        bytes32 existRootHash = settlement.getBatch(batchId-1).rootHash;

        CompleteMerkle merkle = new CompleteMerkle();
        bytes32 rootHash = merkle.getRoot(leaves);
        bytes32 finalRootHash = settlement.generateFinalRootHash(rootHash, existRootHash);
    
        // Submit batch
        // settlement.submitBatch(startBlock, endBlock, items.length, finalRootHash);
        // console.log("Batch submitted");

        // finalize settlement
        settlement.finalizeSettlement(batchId, items);
        console.log("Settlement finalized");

        // query fee balance
        uint256 feeBalance = asset.feeBalance();
        console.log("Fee balance:", feeBalance);

        vm.stopBroadcast();
    }
}