// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ISettlement} from "../src/interfaces/ISettlement.sol";
import {Settlement} from "../src/Settlement.sol";
import {Asset} from "../src/Asset.sol";

import {MockToken} from "../src/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {CompleteMerkle} from "@murky/CompleteMerkle.sol";

contract SettlementTest is Test {
    Asset public asset;
    Settlement public settlement;

    bytes32 public constant ADMIN_ROLE = 0x00;
    // mock token
    MockToken internal USDT = new MockToken("USDT", "USDT");

    // initial addresses
    address internal signer1 = address(0x1);
    address internal signer2 = address(0x2);
    address internal signer3 = address(0x3);
    address internal owner = address(0x4);
    address internal user1 = address(0x5);
    address internal user2 = address(0x6);
    address internal user3 = address(0x7);

    address[] internal signers = [signer1, signer2, signer3];
    address[] internal batchSubmitter = signers;

    function setUp() public {
        vm.startPrank(owner);
        asset = new Asset(address(USDT), signers);
        settlement = new Settlement(address(asset), batchSubmitter);

        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
    }

    function test_setBatchSubmitter() public {
        // invalid owner
        vm.startPrank(signer1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer1));
        settlement.setBatchSubmitter(batchSubmitter);

        // set owner
        vm.startPrank(owner);
        address[] memory emptySubmitter = new address[](0);
        vm.expectRevert("Invalid batch submitter");
        settlement.setBatchSubmitter(emptySubmitter);

        address[] memory newBatchSubmitter = new address[](2);
        newBatchSubmitter[0] = signer1;
        newBatchSubmitter[1] = signer2;
        settlement.setBatchSubmitter(newBatchSubmitter);
        assertEq(settlement.getBatchSubmitter(), newBatchSubmitter);

        vm.stopPrank();
    }

    function test_setAssetContract() public {
        // invalid owner
        vm.startPrank(signer1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer1));
        settlement.setAssetContract(address(asset));

        // set owner
        vm.startPrank(owner);
        vm.expectRevert("Invalid asset contract address");
        settlement.setAssetContract(address(0));

        settlement.setAssetContract(address(asset));
        assertEq(settlement.getAssetContract(), address(asset));

        vm.stopPrank();
    }

    function test_generateLeaf() public view {
        bytes32 leaf = settlement.generateLeaf(
            1,
            ISettlement.SettlementItem({
                orderId: 1,
                businessOrderId: 1,
                user: signer1,
                amount: 1000,
                isAdd: true,
                isSettleFee: false
            })
        );

        console.logBytes32(leaf);

        bytes32 hexStr = hex"46b4568c9394403fefe0eb2c678659efa6e5324acdccfbddfd30294830034863";
        assertEq(leaf, hexStr);
    }

    function test_generateFinalRootHash() public {
        bytes32 batchRootHash = hex"6b9eff06fa285d0f853d4a9ffcc53f3bb34ac0c19588f12c6a0e6b6a0adb2216";
        bytes32 previousRootHash = hex"ad2ef2fb5337f7bb0e17fb479d4676e5a0a0a6d646780da968d7215e2ed1f29a";
        bytes32 finalRootHash = settlement.generateFinalRootHash(batchRootHash, previousRootHash);

        CompleteMerkle merkle = new CompleteMerkle();
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = batchRootHash;
        leaves[1] = previousRootHash;
        bytes32 finalRootHash2 = merkle.getRoot(leaves);
        assertEq(finalRootHash2, finalRootHash);

        bytes32 expectedRootHash = hex"f93598a6a5c1b0858e4167f34ebfc56d5f0c2685e5fab84d74b02ce9d22b995d";
        assertEq(finalRootHash, expectedRootHash);
    }

    function test_submitBatch() public {
        uint256 startBlock = 1;
        // invalid batch submitter
        vm.startPrank(user1);
        vm.expectRevert("Not batch submitter");
        settlement.submitBatch(startBlock, 1, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // valid batch submitter
        vm.startPrank(batchSubmitter[0]);

        // invalid start block
        vm.expectRevert("Invalid start block");
        settlement.submitBatch(0, 1, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // invalid total items
        vm.expectRevert("Invalid total items");
        settlement.submitBatch(startBlock, 0, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // invalid root hash
        vm.expectRevert("Invalid root hash");
        settlement.submitBatch(startBlock, 1, bytes32(0));

        // expect event
        vm.expectEmit(address(settlement));
        emit ISettlement.BatchSubmitted(
            startBlock, 1, 1, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f", bytes32(0)
        );
        // valid batch submitter
        settlement.submitBatch(startBlock, 1, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // check batch info
        uint256 batchId = 1;
        ISettlement.Batch memory batch = settlement.getBatch(batchId);
        assertEq(batch.startBlock, 1);
        assertEq(batch.totalItems, 1);
        assertEq(batch.rootHash, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");
        assertEq(batch.previousRootHash, bytes32(0));

        vm.stopPrank();
    }

    function test_finalizeSettlement() public {
        CompleteMerkle merkle = new CompleteMerkle();
        // generate leaf items

        // item 0 : deposit to user1 1000
        // item 1 : settle fee to asset pool
        // item 2 : settle to user2

        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](3);
        items[0] = ISettlement.SettlementItem({
            orderId: 1,
            businessOrderId: 1,
            user: signer1,
            amount: 1000,
            isAdd: true,
            isSettleFee: false
        });
        items[1] = ISettlement.SettlementItem({
            orderId: 2,
            businessOrderId: 2,
            user: signer2,
            amount: 100,
            isAdd: false,
            isSettleFee: true
        });
        items[2] = ISettlement.SettlementItem({
            orderId: 3,
            businessOrderId: 2,
            user: signer3,
            amount: 500,
            isAdd: true,
            isSettleFee: false
        });

        // generate leaf
        uint256 batchId = 1;
        uint256 startBlock = 1;

        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        leaves[2] = settlement.generateLeaf(batchId, items[2]);
        bytes32 batchRootHash = merkle.getRoot(leaves);

        console.log("leaves");
        console.logBytes32(leaves[0]);
        console.logBytes32(leaves[1]);
        console.logBytes32(leaves[2]);

        console.log("batchRootHash");
        console.logBytes32(batchRootHash);

        // generate final root hash
        bytes32 previousRootHash = bytes32(0);
        bytes32 finalRootHash = settlement.generateFinalRootHash(batchRootHash, previousRootHash);

        console.log("finalRootHash");
        console.logBytes32(finalRootHash);

        // first submit batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, items.length, finalRootHash);

        // finalize settlement use normal user
        vm.startPrank(user1);

        // invalid batchId
        vm.expectRevert("Invalid batchId");
        settlement.finalizeSettlement(batchId + 1, items);

        // mismatch root hash
        ISettlement.SettlementItem[] memory tmpItems = new ISettlement.SettlementItem[](3);
        tmpItems[0] = items[0];
        tmpItems[1] = items[1];
        tmpItems[2] = items[2];
        tmpItems[2].amount = 1001;
        vm.expectRevert("Mismatch root hash");
        settlement.finalizeSettlement(batchId, tmpItems);

        // recover item[2]
        tmpItems[2].amount = 500;
        console.log("item[2]");
        console.logBytes32(settlement.generateLeaf(batchId, items[2]));

        // exec finalizeSettlement
        vm.expectEmit(address(settlement));
        emit ISettlement.Settlement(
            items[0].orderId,
            items[0].businessOrderId,
            items[0].user,
            items[0].amount,
            items[0].isAdd,
            items[0].isSettleFee
        );
        emit ISettlement.Settlement(
            items[1].orderId,
            items[1].businessOrderId,
            items[1].user,
            items[1].amount,
            items[1].isAdd,
            items[1].isSettleFee
        );
        emit ISettlement.Settlement(
            items[2].orderId,
            items[2].businessOrderId,
            items[2].user,
            items[2].amount,
            items[2].isAdd,
            items[2].isSettleFee
        );
        settlement.finalizeSettlement(batchId, items);

        // submit batch 2
        vm.startPrank(batchSubmitter[1]);
        batchId = 2;
        items[2].amount = 1002;

        bytes32[] memory leaves2 = new bytes32[](3);
        leaves2[0] = settlement.generateLeaf(batchId, items[0]);
        leaves2[1] = settlement.generateLeaf(batchId, items[1]);
        leaves2[2] = settlement.generateLeaf(batchId, items[2]);

        bytes32 batchRootHash2 = merkle.getRoot(leaves2);
        console.log("batchRootHash2");
        console.logBytes32(batchRootHash2);

        ISettlement.Batch memory batch = settlement.getBatch(batchId - 1);
        console.log("previousRootHash");
        console.logBytes32(batch.rootHash);

        bytes32 finalRootHash2 = settlement.generateFinalRootHash(batchRootHash2, batch.rootHash);
        console.log("finalRootHash2");
        console.logBytes32(finalRootHash2);

        vm.expectRevert("Invalid startBlock");
        settlement.submitBatch(startBlock, items.length, finalRootHash2);

        settlement.submitBatch(startBlock + items.length, items.length, finalRootHash2);

        vm.expectRevert("Order already exists");
        settlement.finalizeSettlement(batchId, items);

        vm.stopPrank();
    }


     function test_finalizeSettlement_gaslimit() public {
        CompleteMerkle merkle = new CompleteMerkle();
        uint256 itemCount = 100;

        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](itemCount);
        for (uint256 i = 0; i < itemCount; i++) {
            items[i] = ISettlement.SettlementItem({
                orderId: i,
                businessOrderId: i,
                amount: 1000,
                user: signer1,
                isAdd: true,
                isSettleFee: false
            });
        }

        // generate leaf
        uint256 batchId = 1;
        uint256 startBlock = 1;

        bytes32[] memory leaves = new bytes32[](itemCount);
        for (uint256 i = 0; i < itemCount; i++) {
            leaves[i] = settlement.generateLeaf(batchId, items[i]);
        }
        bytes32 batchRootHash = merkle.getRoot(leaves);

        // generate final root hash
        bytes32 previousRootHash = bytes32(0);
        bytes32 finalRootHash = settlement.generateFinalRootHash(batchRootHash, previousRootHash);

        // first submit batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, items.length, finalRootHash);

        // finalize settlement use normal user
        settlement.finalizeSettlement(batchId, items);
        vm.stopPrank();
    }
}
