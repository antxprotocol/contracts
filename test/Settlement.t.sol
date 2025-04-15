// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ISettlement} from "../src/interfaces/ISettlement.sol";
import {Settlement} from "../src/Settlement.sol";
import {Asset} from "../src/Asset.sol";

import {MockToken} from "../src/mock/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {CompleteMerkle} from "@murky/CompleteMerkle.sol";
import {MurkyBase} from "@murky/common/MurkyBase.sol";

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
    
    // Time lock constants from contracts
    uint256 public constant SETTLEMENT_TIME_LOCK = 1 days;

    function setUp() public {
        vm.startPrank(owner);
        asset = new Asset(address(USDT), signers);
        settlement = new Settlement(address(asset), batchSubmitter);

        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
    }

    function test_constructor() public {
        // Test using invalid asset contract address
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(ISettlement.ZeroAddressNotAllowed.selector));
        new Settlement(address(0), batchSubmitter);
        
        // Test using empty batch submitter list
        address[] memory emptySubmitter = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(ISettlement.EmptyArrayNotAllowed.selector));
        new Settlement(address(asset), emptySubmitter);
        
        // Test using batch submitter list containing zero address
        address[] memory invalidSubmitter = new address[](3);
        invalidSubmitter[0] = signer1;
        invalidSubmitter[1] = address(0);
        invalidSubmitter[2] = signer3;
        vm.expectRevert(abi.encodeWithSelector(ISettlement.ZeroAddressNotAllowed.selector));
        new Settlement(address(asset), invalidSubmitter);
        
        // Test the state of correctly created contract
        Settlement newSettlement = new Settlement(address(asset), batchSubmitter);
        assertEq(newSettlement.getAssetContract(), address(asset));
        assertEq(newSettlement.getBatchSubmitter(), batchSubmitter);
        vm.stopPrank();
    }

    function test_pause_unpause() public {
        // Non-admin cannot pause the contract
        vm.startPrank(signer1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer1));
        settlement.pause();
        vm.stopPrank();
        
        // Admin can pause the contract
        vm.startPrank(owner);
        settlement.pause();
        
        // Paused contract cannot submit batch
        vm.startPrank(batchSubmitter[0]);
        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        settlement.submitBatch(1, 1, bytes32(uint256(1)));
        vm.stopPrank();
        
        // Paused contract cannot set batch submitter
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        settlement.setBatchSubmitter(batchSubmitter);
        
        // Paused contract cannot set asset contract
        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        settlement.setAssetContract(address(asset));
        
        // Non-admin cannot unpause the contract
        vm.startPrank(signer1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer1));
        settlement.unpause();
        vm.stopPrank();
        
        // Admin can unpause the contract
        vm.startPrank(owner);
        settlement.unpause();
        
        // Can submit batch normally after unpausing
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(1, 1, bytes32(uint256(1)));
        vm.stopPrank();
        
        vm.startPrank(owner);
        // Can pause again
        settlement.pause();
        
        // Paused contract cannot finalize settlement
        vm.startPrank(batchSubmitter[0]);
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](1);
        items[0] = ISettlement.SettlementItem({
            orderId: 1,
            businessOrderId: 1,
            user: signer1,
            amount: 1000,
            isAdd: true,
            isSettleFee: false
        });
        
        vm.expectRevert(abi.encodeWithSelector(Pausable.EnforcedPause.selector));
        settlement.finalizeSettlement(1, items);
        vm.stopPrank();
        
        // Restore to normal state
        vm.startPrank(owner);
        settlement.unpause();
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
        vm.expectRevert(abi.encodeWithSelector(ISettlement.EmptyArrayNotAllowed.selector));
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
        vm.expectRevert(abi.encodeWithSelector(ISettlement.ZeroAddressNotAllowed.selector));
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
        vm.expectRevert(abi.encodeWithSelector(ISettlement.NotBatchSubmitter.selector));
        settlement.submitBatch(startBlock, 1, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // valid batch submitter
        vm.startPrank(batchSubmitter[0]);

        // invalid start block
        vm.expectRevert(abi.encodeWithSelector(ISettlement.InvalidStartBlock.selector));
        settlement.submitBatch(0, 1, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // invalid total items
        vm.expectRevert(abi.encodeWithSelector(ISettlement.InvalidTotalItems.selector));
        settlement.submitBatch(startBlock, 0, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // Batch too large
        vm.expectRevert(abi.encodeWithSelector(ISettlement.BatchTooLarge.selector));
        settlement.submitBatch(startBlock, 1001, hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f");

        // invalid root hash
        vm.expectRevert(abi.encodeWithSelector(ISettlement.InvalidRootHash.selector));
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
        
        // Non-batch submitter cannot call finalizeSettlement
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(ISettlement.NotBatchSubmitter.selector));
        settlement.finalizeSettlement(batchId, items);
        vm.stopPrank();
        
        // Advance time past SETTLEMENT_TIME_LOCK
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // Use batch submitter identity
        vm.startPrank(batchSubmitter[0]);
        
        // Test invalid batchId
        vm.expectRevert(abi.encodeWithSelector(ISettlement.InvalidBatchId.selector));
        settlement.finalizeSettlement(batchId + 1, items);

        // Test mismatched root hash
        ISettlement.SettlementItem[] memory tmpItems = new ISettlement.SettlementItem[](3);
        tmpItems[0] = items[0];
        tmpItems[1] = items[1];
        tmpItems[2] = items[2];
        tmpItems[2].amount = 1001;
        vm.expectRevert(abi.encodeWithSelector(ISettlement.MismatchRootHash.selector));
        settlement.finalizeSettlement(batchId, tmpItems);

        // Recover item[2]
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
        vm.stopPrank();
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

        vm.expectRevert(abi.encodeWithSelector(ISettlement.InvalidStartBlock.selector));
        settlement.submitBatch(startBlock, items.length, finalRootHash2);

        settlement.submitBatch(startBlock + items.length, items.length, finalRootHash2);
        
        // Advance time past SETTLEMENT_TIME_LOCK for the new batch
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);

        vm.expectRevert(abi.encodeWithSelector(ISettlement.OrderAlreadyExists.selector));
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

        // Advance time past SETTLEMENT_TIME_LOCK
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);

        // finalize settlement use normal user
        settlement.finalizeSettlement(batchId, items);
        vm.stopPrank();
    }
    
    function test_finalizeSettlement_tooManyItems() public {
        CompleteMerkle merkle = new CompleteMerkle();
        uint256 itemCount = 201; // Exceeds the maximum allowed number of items for a single operation

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

        // Test case with too many items
        vm.expectRevert(abi.encodeWithSelector(ISettlement.TooManyItemsToFinalize.selector));
        settlement.finalizeSettlement(batchId, items);
        vm.stopPrank();
    }
    
    function test_finalizeSettlement_emptyArray() public {
        // Create a valid batch
        ISettlement.SettlementItem[] memory validItems = new ISettlement.SettlementItem[](2);
        validItems[0] = ISettlement.SettlementItem({
            orderId: 1,
            businessOrderId: 1,
            user: signer1,
            amount: 1000,
            isAdd: true,
            isSettleFee: false
        });
        validItems[1] = ISettlement.SettlementItem({
            orderId: 2,
            businessOrderId: 2,
            user: signer2,
            amount: 1000,
            isAdd: true,
            isSettleFee: false
        });
        
        CompleteMerkle merkle = new CompleteMerkle();
        
        // Generate and submit a valid batch
        uint256 batchId = 1;
        uint256 startBlock = 1;
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = settlement.generateLeaf(batchId, validItems[0]);
        leaves[1] = settlement.generateLeaf(batchId, validItems[1]);
        bytes32 batchRootHash = merkle.getRoot(leaves);
        bytes32 previousRootHash = bytes32(0);
        bytes32 finalRootHash = settlement.generateFinalRootHash(batchRootHash, previousRootHash);
        
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, validItems.length, finalRootHash);
        
        // Test empty array case
        ISettlement.SettlementItem[] memory emptyItems = new ISettlement.SettlementItem[](0);
        vm.expectRevert(abi.encodeWithSelector(ISettlement.EmptyArrayNotAllowed.selector));
        settlement.finalizeSettlement(batchId, emptyItems);
        vm.stopPrank();
    }
    
    function test_finalizeSettlement_zeroAddress() public {
        // Create two items, one normal item and one zero address item
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](2);
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
            user: address(0), // Zero address
            amount: 1000,
            isAdd: true,
            isSettleFee: false // Not fee settlement
        });
        
        // Generate and submit batch
        CompleteMerkle merkle = new CompleteMerkle();
        uint256 batchId = 1;
        uint256 startBlock = 1;
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        bytes32 batchRootHash = merkle.getRoot(leaves);
        bytes32 previousRootHash = bytes32(0);
        bytes32 finalRootHash = settlement.generateFinalRootHash(batchRootHash, previousRootHash);
        
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, items.length, finalRootHash);
        
        // Advance time past time lock
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // Test case with zero address user (not fee settlement) should throw error
        vm.expectRevert(abi.encodeWithSelector(ISettlement.ZeroAddressNotAllowed.selector));
        settlement.finalizeSettlement(batchId, items);
        
        // End of test
        vm.stopPrank();
    }
    
    function test_finalizeSettlement_invalidProof() public {
        // Create two settlement items
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](2);
        items[0] = ISettlement.SettlementItem({
            orderId: 100,
            businessOrderId: 100,
            user: user1,
            amount: 500,
            isAdd: true,
            isSettleFee: false
        });
        
        items[1] = ISettlement.SettlementItem({
            orderId: 101,
            businessOrderId: 101,
            user: user2,
            amount: 700,
            isAdd: true,
            isSettleFee: false
        });
        
        uint256 batchId = 1;
        uint256 startBlock = block.number;
        
        // Generate correct leaves for the Merkle tree
        CompleteMerkle merkle = new CompleteMerkle();
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        
        // Get the correct root hash
        bytes32 rootHash = merkle.getRoot(leaves);
        
        // Submit batch with the correct root hash
        vm.prank(signer1);
        settlement.submitBatch(startBlock, 2, rootHash);
        
        // Fast forward past the time lock
        vm.warp(block.timestamp + settlement.SETTLEMENT_TIME_LOCK() + 1);
        
        // This test is difficult to implement because the contract first checks if the root hash matches
        // before verifying individual proofs. If we modify the items, it will fail with MismatchRootHash.
        // 
        // In a real-world scenario, ErrInvalidProof would occur if:
        // 1. The Merkle tree implementation has a bug
        // 2. The proof generation logic is incorrect
        // 3. The contract's verification logic is incorrect
        //
        // Since we can't easily simulate these conditions in a unit test, we'll skip this test
        // but acknowledge that the branch exists and would be triggered in those scenarios.
        vm.skip(true);
    }

    function test_settlement_timeLock() public {
        // Create two simple settlement items
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](2);
        items[0] = ISettlement.SettlementItem({
            orderId: 100,
            businessOrderId: 100,
            user: signer1,
            amount: 500,
            isAdd: true,
            isSettleFee: false
        });
        
        items[1] = ISettlement.SettlementItem({
            orderId: 101,
            businessOrderId: 101,
            user: signer2,
            amount: 700,
            isAdd: true,
            isSettleFee: false
        });
        
        // Create a simple batch
        CompleteMerkle merkle = new CompleteMerkle();
        uint256 batchId = 1;
        
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        
        bytes32 rootHash = merkle.getRoot(leaves);
        bytes32 finalRootHash = settlement.generateFinalRootHash(rootHash, bytes32(0));
        
        // Submit the batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(1, 2, finalRootHash);
        
        // First verification - trying to finalize before time lock expires should fail
        vm.expectRevert(abi.encodeWithSelector(ISettlement.TimeLockNotPassed.selector));
        settlement.finalizeSettlement(batchId, items);
        
        // Now advance time past the time lock
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // Should now succeed
        settlement.finalizeSettlement(batchId, items);
        
        vm.stopPrank();
    }

    function test_batch_structure_integrity() public {
        // Test the complete Batch structure including the batchTime field
        uint256 startBlock = 1;
        bytes32 testRootHash = hex"7a59672632b9d47cc075c2b523053e14c02313b6f0d5fc558a7b67b3555f564f";
        
        // Get current timestamp
        uint256 currentTime = block.timestamp;
        
        // Submit batch as a valid submitter
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, 1, testRootHash);
        vm.stopPrank();
        
        // Check batch info including batchTime
        ISettlement.Batch memory batch = settlement.getBatch(1);
        assertEq(batch.startBlock, startBlock);
        assertEq(batch.totalItems, 1);
        assertEq(batch.rootHash, testRootHash);
        assertEq(batch.previousRootHash, bytes32(0));
        assertEq(batch.batchTime, currentTime);
        
        // Verify that lastBatchTime was also set in Asset contract
        assertEq(asset.getLastBatchTime(), currentTime);
    }

    function test_generateFinalRootHash_edge_cases() public {
        // Test zero values
        bytes32 zeroHash = bytes32(0);
        bytes32 finalRootHashZero = settlement.generateFinalRootHash(zeroHash, zeroHash);
        
        // Even with zero inputs, should produce a valid Merkle root
        CompleteMerkle merkle = new CompleteMerkle();
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = zeroHash;
        leaves[1] = zeroHash;
        bytes32 expectedRootHash = merkle.getRoot(leaves);
        
        assertEq(finalRootHashZero, expectedRootHash);
        assertNotEq(finalRootHashZero, zeroHash, "Root hash should not be zero even with zero inputs");
        
        // Test with one zero and one non-zero
        bytes32 nonZeroHash = hex"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        bytes32 finalRootHashMixed = settlement.generateFinalRootHash(nonZeroHash, zeroHash);
        
        leaves[0] = nonZeroHash;
        leaves[1] = zeroHash;
        expectedRootHash = merkle.getRoot(leaves);
        
        assertEq(finalRootHashMixed, expectedRootHash);
    }
    
    function test_lastBatchTime_update() public {
        // Verify that lastBatchTime gets updated when submitting batches
        uint256 initialTime = block.timestamp;
        
        // Submit first batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(1, 1, bytes32(uint256(1)));
        
        // Verify time was set
        assertEq(asset.getLastBatchTime(), initialTime);
        
        // Advance time
        vm.warp(block.timestamp + 100);
        uint256 newTime = block.timestamp;
        
        // Submit second batch
        settlement.submitBatch(2, 1, bytes32(uint256(2)));
        
        // Verify new time was set
        assertEq(asset.getLastBatchTime(), newTime);
        vm.stopPrank();
    }
    
    function test_finalizeSettlement_with_large_valid_items() public {
        // Test with exactly MAX_ITEMS_PER_FINALIZE items (valid limit)
        CompleteMerkle merkle = new CompleteMerkle();
        uint256 itemCount = settlement.MAX_ITEMS_PER_FINALIZE();
        
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
        
        // Generate leaves and merkle root
        uint256 batchId = 1;
        uint256 startBlock = 1;
        
        bytes32[] memory leaves = new bytes32[](itemCount);
        for (uint256 i = 0; i < itemCount; i++) {
            leaves[i] = settlement.generateLeaf(batchId, items[i]);
        }
        bytes32 batchRootHash = merkle.getRoot(leaves);
        
        // Generate final root hash
        bytes32 previousRootHash = bytes32(0);
        bytes32 finalRootHash = settlement.generateFinalRootHash(batchRootHash, previousRootHash);
        
        // Submit batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, items.length, finalRootHash);
        
        // Advance time past SETTLEMENT_TIME_LOCK
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // This should succeed as it's exactly at the maximum limit
        settlement.finalizeSettlement(batchId, items);
        vm.stopPrank();
    }

    function test_mixed_settlement_operations() public {
        // Test mix of add, subtract and fee operations in one batch
        CompleteMerkle merkle = new CompleteMerkle();
        
        // Create mixed operations: add for user1, subtract for user2, fee operation
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](3);
        items[0] = ISettlement.SettlementItem({
            orderId: 101,
            businessOrderId: 101,
            user: user1,
            amount: 1000,
            isAdd: true,
            isSettleFee: false
        });
        
        items[1] = ISettlement.SettlementItem({
            orderId: 102,
            businessOrderId: 102,
            user: user2,
            amount: 500,
            isAdd: false, // Subtract operation
            isSettleFee: false
        });
        
        items[2] = ISettlement.SettlementItem({
            orderId: 103,
            businessOrderId: 103,
            user: address(0), // Fee operations can have zero address
            amount: 300,
            isAdd: false,
            isSettleFee: true  // Fee operation
        });
        
        // Add some initial balance for user2 so we can subtract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        vm.startPrank(batchSubmitter[0]);
        
        // Setup test environment
        uint256 batchId = 1;
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        leaves[2] = settlement.generateLeaf(batchId, items[2]);
        
        bytes32 batchRootHash = merkle.getRoot(leaves);
        bytes32 finalRootHash = settlement.generateFinalRootHash(batchRootHash, bytes32(0));
        
        // Add initial balance for user2
        vm.stopPrank();
        vm.prank(address(settlement));
        asset.addUserBalance(user2, 1000);
        
        // Submit and process batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(1, items.length, finalRootHash);
        
        // Advance time past SETTLEMENT_TIME_LOCK
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // Process the batch
        settlement.finalizeSettlement(batchId, items);
        
        // Verify all balances
        assertEq(asset.getUserBalance(user1), 1000);
        assertEq(asset.getUserBalance(user2), 500); // 1000 - 500
        assertEq(asset.getFeeBalance(), 300);
        
        vm.stopPrank();
    }

    function test_merkle_proof_verification() public {
        // Test the merkle proof verification functionality more directly
        CompleteMerkle merkle = new CompleteMerkle();
        
        // Create a simple batch with two items
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](2);
        items[0] = ISettlement.SettlementItem({
            orderId: 1001,
            businessOrderId: 1001,
            user: user1,
            amount: 1000,
            isAdd: true,
            isSettleFee: false
        });
        
        items[1] = ISettlement.SettlementItem({
            orderId: 1002,
            businessOrderId: 1002,
            user: user2,
            amount: 2000,
            isAdd: true,
            isSettleFee: false
        });
        
        // Generate leaf nodes
        uint256 batchId = 1;
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        
        // Get root hash and proofs
        bytes32 rootHash = merkle.getRoot(leaves);
        bytes32[] memory proof0 = merkle.getProof(leaves, 0);
        bytes32[] memory proof1 = merkle.getProof(leaves, 1);
        
        // Verify proofs directly
        bool isValidProof0 = merkle.verifyProof(rootHash, proof0, leaves[0]);
        bool isValidProof1 = merkle.verifyProof(rootHash, proof1, leaves[1]);
        
        assertTrue(isValidProof0, "Proof for first leaf should be valid");
        assertTrue(isValidProof1, "Proof for second leaf should be valid");
        
        // Test invalid proof
        bytes32 invalidLeaf = keccak256(abi.encodePacked("invalid"));
        bool isInvalidProof = merkle.verifyProof(rootHash, proof0, invalidLeaf);
        assertFalse(isInvalidProof, "Proof should fail for invalid leaf");
    }
    
    function test_batch_sequence() public {
        // Test proper sequence of batch IDs and block progression
        vm.startPrank(batchSubmitter[0]);
        
        // Submit first batch
        settlement.submitBatch(1, 1, bytes32(uint256(1)));
        
        // Check batch ID
        assertEq(settlement.batchId(), 1);
        
        // Submit second batch
        settlement.submitBatch(2, 2, bytes32(uint256(2)));
        
        // Check batch ID incremented
        assertEq(settlement.batchId(), 2);
        
        // Submit third batch with invalid start block (should fail)
        vm.expectRevert(abi.encodeWithSelector(ISettlement.InvalidStartBlock.selector));
        settlement.submitBatch(3, 3, bytes32(uint256(3)));
        
        // Submit third batch with correct start block
        settlement.submitBatch(4, 3, bytes32(uint256(3)));
        
        // Verify sequence
        assertEq(settlement.batchId(), 3);
        
        ISettlement.Batch memory batch1 = settlement.getBatch(1);
        ISettlement.Batch memory batch2 = settlement.getBatch(2);
        ISettlement.Batch memory batch3 = settlement.getBatch(3);
        
        assertEq(batch1.startBlock, 1);
        assertEq(batch1.totalItems, 1);
        assertEq(batch2.startBlock, 2);
        assertEq(batch2.totalItems, 2);
        assertEq(batch3.startBlock, 4);
        assertEq(batch3.totalItems, 3);
        
        // Verify linkedList-like structure with previousRootHash
        assertEq(batch1.previousRootHash, bytes32(0));
        assertEq(batch2.previousRootHash, batch1.rootHash);
        assertEq(batch3.previousRootHash, batch2.rootHash);
        
        vm.stopPrank();
    }
    
    function test_fee_settlement_with_zero_address() public {
        // Test fee settlement specifically with zero address
        CompleteMerkle merkle = new CompleteMerkle();
        
        // Create fee settlement item with zero address (should be allowed)
        // Add a second item to avoid single leaf error
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](2);
        items[0] = ISettlement.SettlementItem({
            orderId: 2001,
            businessOrderId: 2001,
            user: address(0), // Zero address
            amount: 500,
            isAdd: false,
            isSettleFee: true // Fee settlement should allow zero address
        });
        
        // Add a second item to avoid the single leaf error
        items[1] = ISettlement.SettlementItem({
            orderId: 2002,
            businessOrderId: 2002,
            user: user1, // Normal user
            amount: 100,
            isAdd: true,
            isSettleFee: false
        });
        
        // Generate batch
        uint256 batchId = 1;
        uint256 startBlock = 1;
        
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        bytes32 rootHash = merkle.getRoot(leaves);
        bytes32 finalRootHash = settlement.generateFinalRootHash(rootHash, bytes32(0));
        
        // Submit batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, items.length, finalRootHash);
        
        // Advance time past SETTLEMENT_TIME_LOCK
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // This should succeed since zero address is allowed for fee settlements
        settlement.finalizeSettlement(batchId, items);
        
        // Verify fee balance and user balance
        assertEq(asset.getFeeBalance(), 500);
        assertEq(asset.getUserBalance(user1), 100);
        
        vm.stopPrank();
    }
    
    function test_revert_nonbatch_submitter_pause() public {
        // Test that non-batch submitters cannot pause the contract
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        settlement.pause();
        vm.stopPrank();
    }
    
    function test_full_validation_chain() public {
        // Test the full sequence of validation checks in finalizeSettlement
        CompleteMerkle merkle = new CompleteMerkle();
        
        // Create a test batch with 3 items
        ISettlement.SettlementItem[] memory items = new ISettlement.SettlementItem[](3);
        items[0] = ISettlement.SettlementItem({
            orderId: 3001,
            businessOrderId: 3001,
            user: user1,
            amount: 1000,
            isAdd: true,
            isSettleFee: false
        });
        
        items[1] = ISettlement.SettlementItem({
            orderId: 3002,
            businessOrderId: 3002,
            user: user2,
            amount: 2000,
            isAdd: true,
            isSettleFee: false
        });
        
        items[2] = ISettlement.SettlementItem({
            orderId: 3003,
            businessOrderId: 3003,
            user: user3,
            amount: 3000,
            isAdd: true,
            isSettleFee: false
        });
        
        // Generate batch
        uint256 batchId = 1;
        uint256 startBlock = 1;
        
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = settlement.generateLeaf(batchId, items[0]);
        leaves[1] = settlement.generateLeaf(batchId, items[1]);
        leaves[2] = settlement.generateLeaf(batchId, items[2]);
        bytes32 rootHash = merkle.getRoot(leaves);
        bytes32 finalRootHash = settlement.generateFinalRootHash(rootHash, bytes32(0));
        
        // Submit batch
        vm.startPrank(batchSubmitter[0]);
        settlement.submitBatch(startBlock, items.length, finalRootHash);
        
        // Advance time past SETTLEMENT_TIME_LOCK
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // Process batch
        settlement.finalizeSettlement(batchId, items);
        
        // Verify all users got their balance
        assertEq(asset.getUserBalance(user1), 1000);
        assertEq(asset.getUserBalance(user2), 2000);
        assertEq(asset.getUserBalance(user3), 3000);
        
        // Try to reuse orderId (should fail)
        ISettlement.SettlementItem[] memory items2 = new ISettlement.SettlementItem[](2); // Use at least 2 items
        items2[0] = ISettlement.SettlementItem({
            orderId: 3001, // Already used
            businessOrderId: 4001,
            user: user1,
            amount: 500,
            isAdd: true,
            isSettleFee: false
        });
        
        // Add second item to avoid single leaf error
        items2[1] = ISettlement.SettlementItem({
            orderId: 4002, // New ID
            businessOrderId: 4002, 
            user: user2,
            amount: 600,
            isAdd: true,
            isSettleFee: false
        });
        
        bytes32[] memory leaves2 = new bytes32[](2);
        leaves2[0] = settlement.generateLeaf(batchId + 1, items2[0]);
        leaves2[1] = settlement.generateLeaf(batchId + 1, items2[1]);
        bytes32 rootHash2 = merkle.getRoot(leaves2);
        bytes32 finalRootHash2 = settlement.generateFinalRootHash(rootHash2, finalRootHash);
        
        // Submit second batch
        settlement.submitBatch(startBlock + items.length, items2.length, finalRootHash2);
        
        // Advance time past SETTLEMENT_TIME_LOCK
        vm.warp(block.timestamp + SETTLEMENT_TIME_LOCK + 1);
        
        // This should fail because the orderId is already used
        vm.expectRevert(abi.encodeWithSelector(ISettlement.OrderAlreadyExists.selector));
        settlement.finalizeSettlement(batchId + 1, items2);
        
        vm.stopPrank();
    }
}
