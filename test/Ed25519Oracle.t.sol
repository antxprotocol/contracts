// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Ed25519Oracle} from "../src/oracle/oracle.sol";
import {IEd25519Oracle} from "../src/interfaces/IEd25519Oracle.sol";

/**
 * @title Ed25519OracleTest
 * @dev Test suite for Ed25519Oracle contract
 */
contract Ed25519OracleTest is Test {
    Ed25519Oracle public oracle;
    
    // Test addresses
    address public owner;
    address public node1;
    address public node2;
    address public node3;
    address public node4;
    
    // Test data
    bytes32 public constant TEST_PUBLIC_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    bytes32 public constant TEST_MESSAGE_HASH = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;
    bytes public constant TEST_SIGNATURE = hex"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    uint256 public constant MINIMUM_STAKE = 1 ether;
    uint256 public constant CONSENSUS_THRESHOLD = 5000; // 50%
    uint256 public constant CONSENSUS_TIMEOUT = 300; // 5 minutes
    uint256 public constant MAX_DATA_AGE = 3600; // 1 hour
    
    function setUp() public {
        owner = address(this);
        node1 = makeAddr("node1");
        node2 = makeAddr("node2");
        node3 = makeAddr("node3");
        node4 = makeAddr("node4");
        
        // Deploy oracle
        oracle = new Ed25519Oracle(
            MINIMUM_STAKE,
            CONSENSUS_THRESHOLD,
            CONSENSUS_TIMEOUT,
            MAX_DATA_AGE
        );
        
        // Fund test addresses
        vm.deal(node1, 10 ether);
        vm.deal(node2, 10 ether);
        vm.deal(node3, 10 ether);
        vm.deal(node4, 10 ether);
    }
    
    // ============ Node Management Tests ============
    
    function testRegisterNode() public {
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        (bool isActive, uint256 stake, uint256 reputation, uint256 lastActivity, bool isRegistered) = oracle.getNodeInfo(node1);
        
        assertTrue(isRegistered);
        assertTrue(isActive);
        assertEq(stake, 2 ether);
        assertEq(reputation, 1000);
        assertTrue(lastActivity > 0);
        
        address[] memory nodes = oracle.getAllNodes();
        assertEq(nodes.length, 2); // Owner + node1
    }
    
    function testRegisterNodeInsufficientStake() public {
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.InsufficientStake.selector);
        oracle.registerNode{value: 0.5 ether}(node1, 0.5 ether);
    }
    
    function testUpdateStake() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Update stake
        vm.prank(node1);
        oracle.updateStake{value: 1 ether}(3 ether);
        
        (bool isActive, uint256 stake, , , bool isRegistered) = oracle.getNodeInfo(node1);
        assertEq(stake, 3 ether);
    }
    
    function testUnregisterNode() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        uint256 initialBalance = node1.balance;
        
        // Unregister node
        vm.prank(owner);
        oracle.unregisterNode(node1);
        
        (, , , , bool isRegistered) = oracle.getNodeInfo(node1);
        assertFalse(isRegistered);
        
        // Check stake was returned
        assertEq(node1.balance, initialBalance + 2 ether);
    }

    function testUnregisterNodeRemovesFromMiddle() public {
        // Register two nodes so that node list is [owner, node1, node2]
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);

        address[] memory beforeNodes = oracle.getAllNodes();
        assertEq(beforeNodes.length, 3);
        assertEq(beforeNodes[0], owner);
        assertEq(beforeNodes[1], node1);
        assertEq(beforeNodes[2], node2);

        // Unregister node1 which is in the middle; this triggers swap-with-last and pop
        vm.prank(owner);
        oracle.unregisterNode(node1);

        address[] memory afterNodes = oracle.getAllNodes();
        assertEq(afterNodes.length, 2);
        assertEq(afterNodes[0], owner);
        assertEq(afterNodes[1], node2);
    }

    function testUnregisterOwnerRemovesHead() public {
        // Register two nodes so that node list is [owner, node1, node2]
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);

        address[] memory beforeNodes = oracle.getAllNodes();
        assertEq(beforeNodes.length, 3);
        assertEq(beforeNodes[0], owner);

        // Unregister owner at index 0, triggers swap-with-last and pop
        vm.prank(owner);
        oracle.unregisterNode(owner);

        address[] memory afterNodes = oracle.getAllNodes();
        assertEq(afterNodes.length, 2);
        // Owner should be gone; remaining should be node1 and node2 in any order
        assertTrue(afterNodes[0] == node1 || afterNodes[0] == node2);
        assertTrue(afterNodes[1] == node1 || afterNodes[1] == node2);
        assertTrue(afterNodes[0] != owner && afterNodes[1] != owner);
    }

    function testUnregisterNodeRemovesTail() public {
        // Register two nodes so that node list is [owner, node1, node2]
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);

        address[] memory beforeNodes = oracle.getAllNodes();
        assertEq(beforeNodes.length, 3);
        assertEq(beforeNodes[2], node2);

        // Unregister the tail element; still executes assignment and pop
        vm.prank(owner);
        oracle.unregisterNode(node2);

        address[] memory afterNodes = oracle.getAllNodes();
        assertEq(afterNodes.length, 2);
        // Tail removed; remaining should be owner and node1
        assertTrue(
            (afterNodes[0] == owner && afterNodes[1] == node1) ||
            (afterNodes[0] == node1 && afterNodes[1] == owner)
        );
    }
    
    // ============ Proof Submission Tests ============
    
    function testSubmitProof() public {
        // Register nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node3, 2 ether);
        
        // Submit proofs
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        vm.prank(node2);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        vm.prank(node3);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, false);
        
        // Check consensus data
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, bool isFinalized, bool finalResult, , ) = oracle.getConsensusData(dataId);
        
        assertEq(validVotes, 2);
        assertEq(invalidVotes, 1);
        assertEq(totalVotes, 3);
        assertTrue(isFinalized);
        assertTrue(finalResult); // More valid votes than invalid
    }

    function testRequiredVotesZeroBranch() public {
        // Deploy oracle with extremely low threshold so requiredVotes initially computes to 0
        Ed25519Oracle lowThresholdOracle = new Ed25519Oracle(
            MINIMUM_STAKE,
            1, // 0.01% threshold so (2 * 1) / 10000 = 0
            CONSENSUS_TIMEOUT,
            MAX_DATA_AGE
        );

        // Register two staked nodes
        vm.deal(node1, 10 ether);
        vm.deal(node2, 10 ether);
        vm.prank(address(this));
        lowThresholdOracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(address(this));
        lowThresholdOracle.registerNode{value: 2 ether}(node2, 2 ether);

        // Submit a single vote; requiredVotes will be corrected to 2, so not finalized
        vm.prank(node1);
        lowThresholdOracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);

        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        ( , , uint256 totalVotes, bool isFinalized, , , ) = lowThresholdOracle.getConsensusData(dataId);
        assertEq(totalVotes, 1);
        assertFalse(isFinalized);
    }
    
    function testSubmitProofConsensusNotReached() public {
        // Register only one node
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Submit proof
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Check consensus data
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, bool isFinalized, bool finalResult, , ) = oracle.getConsensusData(dataId);
        
        assertEq(validVotes, 1);
        assertEq(invalidVotes, 0);
        assertEq(totalVotes, 1);
        assertFalse(isFinalized); // Not enough votes for consensus
        assertFalse(finalResult);
    }
    
    function testSubmitProofDuplicateVote() public {
        // Register node
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Submit proof twice
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, false); // Different vote
        
        // Check that only first vote counts
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, , , , ) = oracle.getConsensusData(dataId);
        
        assertEq(validVotes, 1);
        assertEq(invalidVotes, 0);
        assertEq(totalVotes, 1);
    }
    
    function testSubmitProofOnlyRegisteredNode() public {
        vm.prank(node1);
        vm.expectRevert(Ed25519Oracle.OnlyActiveNode.selector);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
    }
    
    // ============ Query Tests ============
    
    function testIsVerified() public {
        // Register nodes and reach consensus
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        vm.prank(node2);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Check verification
        assertTrue(oracle.isVerified(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
    }
    
    function testIsVerifiedNotFinalized() public {
        // Register only one node
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Check verification (should be false as no consensus)
        assertFalse(oracle.isVerified(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
    }
    
    // ============ Admin Function Tests ============
    
    function testUpdateParameters() public {
        vm.prank(owner);
        oracle.updateParameters(2 ether, 6000, 600, 7200);
        
        (uint256 totalNodes, uint256 totalStakeAmount, uint256 minStake, uint256 consensusThresh, uint256 consensusTime, uint256 maxAge) = oracle.getOracleStats();
        
        assertEq(minStake, 2 ether);
        assertEq(consensusThresh, 6000);
        assertEq(consensusTime, 600);
        assertEq(maxAge, 7200);
    }
    
    function testUpdateParametersInvalidThreshold() public {
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.InvalidConsensusThreshold.selector);
        oracle.updateParameters(2 ether, 15000, 600, 7200); // > 100%
    }
    
    function testUpdateParametersInvalidTimeout() public {
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.InvalidTimeout.selector);
        oracle.updateParameters(2 ether, 6000, 0, 7200); // Zero timeout
    }
    
    function testUpdateNodeReputation() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Update reputation
        vm.prank(owner);
        oracle.updateNodeReputation(node1, 1500);
        
        (, , uint256 reputation, , ) = oracle.getNodeInfo(node1);
        assertEq(reputation, 1500);
    }
    
    function testSetNodeActive() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Deactivate node
        vm.prank(owner);
        oracle.setNodeActive(node1, false);
        
        (bool isActive, , , , ) = oracle.getNodeInfo(node1);
        assertFalse(isActive);
    }

    function testSetNodeActiveReactivate() public {
        // Register node
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);

        // Deactivate
        vm.prank(owner);
        oracle.setNodeActive(node1, false);

        // Reactivate
        vm.prank(owner);
        oracle.setNodeActive(node1, true);

        (bool isActive, , , , ) = oracle.getNodeInfo(node1);
        assertTrue(isActive);
    }
    
    function testEmergencyFinalize() public {
        // Register nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        
        // Submit some proofs
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        
        // Emergency finalize
        vm.prank(owner);
        oracle.emergencyFinalize(dataId, true);
        
        assertTrue(oracle.isVerified(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
    }

    // Cover _checkConsensus timeout branch lines 252..259 and post-timeout flow
    function testConsensusTimeoutFinalizesFalse() public {
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);

        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);

        // warp beyond timeout
        vm.warp(block.timestamp + CONSENSUS_TIMEOUT + 5);

        // trigger _checkConsensus via another submit (duplicate vote ignored but timeout processed)
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);

        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (,, , bool isFinalized, bool finalResult,,) = oracle.getConsensusData(dataId);
        assertTrue(isFinalized);
        assertFalse(finalResult);
    }
    
    // ============ Edge Case Tests ============
    
    function testDataExpiration() public {
        // Register nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Submit proof
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Fast forward time beyond max data age
        vm.warp(block.timestamp + MAX_DATA_AGE + 1);
        
        // Try to submit another proof (should fail)
        vm.prank(node1);
        vm.expectRevert(Ed25519Oracle.DataExpiredError.selector);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
    }
    
    function testConsensusTimeout() public {
        // Register nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Submit proof
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Fast forward time beyond consensus timeout
        vm.warp(block.timestamp + CONSENSUS_TIMEOUT + 1);
        
        // Try to submit another proof (should trigger timeout)
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Check that data was marked as expired
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, bool isFinalized, bool finalResult, , ) = oracle.getConsensusData(dataId);
        
        assertTrue(isFinalized);
        assertFalse(finalResult); // Should be false due to timeout
    }
    
    function testOracleStats() public {
        // Register multiple nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 3 ether}(node2, 3 ether);
        vm.prank(owner);
        oracle.registerNode{value: 1 ether}(node3, 1 ether);
        
        (uint256 totalNodes, uint256 totalStakeAmount, uint256 minStake, uint256 consensusThresh, uint256 consensusTime, uint256 maxAge) = oracle.getOracleStats();
        
        assertEq(totalNodes, 4); // Owner + 3 nodes
        assertEq(totalStakeAmount, 6 ether); // 2 + 3 + 1
        assertEq(minStake, MINIMUM_STAKE);
        assertEq(consensusThresh, CONSENSUS_THRESHOLD);
        assertEq(consensusTime, CONSENSUS_TIMEOUT);
        assertEq(maxAge, MAX_DATA_AGE);
    }

    function testGetAllNodesListUpdates() public {
        // Initially only owner is registered
        address[] memory nodesBefore = oracle.getAllNodes();
        assertEq(nodesBefore.length, 1);

        // Register two nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 3 ether}(node2, 3 ether);

        address[] memory nodesAfter = oracle.getAllNodes();
        // Owner + node1 + node2
        assertEq(nodesAfter.length, 3);

        // Unregister node1 and ensure list shrinks
        vm.prank(owner);
        oracle.unregisterNode(node1);

        address[] memory nodesFinal = oracle.getAllNodes();
        assertEq(nodesFinal.length, 2);
    }
    
    // ============ Additional Comprehensive Tests ============
    
    function testRegisterNodeAlreadyRegistered() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Try to register same node again
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.NodeAlreadyRegistered.selector);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
    }
    
    function testUnregisterNodeNotRegistered() public {
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.NodeNotRegistered.selector);
        oracle.unregisterNode(node1);
    }
    
    function testUpdateStakeNotRegistered() public {
        vm.prank(node1);
        vm.expectRevert(Ed25519Oracle.NodeNotRegistered.selector);
        oracle.updateStake{value: 2 ether}(2 ether);
    }
    
    function testUpdateStakeInsufficientStake() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Try to update to insufficient stake
        vm.prank(node1);
        vm.expectRevert(Ed25519Oracle.InsufficientStake.selector);
        oracle.updateStake{value: 0}(0.5 ether);
    }
    
    function testUpdateStakeDecrease() public {
        // Register node with 3 ether
        vm.prank(owner);
        oracle.registerNode{value: 3 ether}(node1, 3 ether);
        
        uint256 initialBalance = node1.balance;
        
        // Decrease stake to 1 ether
        vm.prank(node1);
        oracle.updateStake{value: 0}(1 ether);
        
        (, uint256 stake, , , ) = oracle.getNodeInfo(node1);
        assertEq(stake, 1 ether);
        assertEq(node1.balance, initialBalance + 2 ether); // Should receive 2 ether back
    }
    
    function testUpdateStakeIncrease() public {
        // Register node with 1 ether
        vm.prank(owner);
        oracle.registerNode{value: 1 ether}(node1, 1 ether);
        
        uint256 initialBalance = node1.balance;
        
        // Increase stake to 3 ether
        vm.prank(node1);
        oracle.updateStake{value: 2 ether}(3 ether);
        
        (, uint256 stake, , , ) = oracle.getNodeInfo(node1);
        assertEq(stake, 3 ether);
        assertEq(node1.balance, initialBalance - 2 ether); // Should pay 2 ether more
    }
    
    function testSubmitProofDataExpired() public {
        // Register node
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Submit proof
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Fast forward time beyond max data age
        vm.warp(block.timestamp + MAX_DATA_AGE + 1);
        
        // Try to submit new proof with same data (should fail)
        vm.prank(node1);
        vm.expectRevert(Ed25519Oracle.DataExpiredError.selector);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
    }
    
    function testSubmitProofInactiveNode() public {
        // Register node
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Deactivate node
        vm.prank(owner);
        oracle.setNodeActive(node1, false);
        
        // Try to submit proof (should fail)
        vm.prank(node1);
        vm.expectRevert(Ed25519Oracle.OnlyActiveNode.selector);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
    }
    
    function testConsensusWithTie() public {
        // Require all votes to finalize
        vm.prank(owner);
        oracle.updateParameters(MINIMUM_STAKE, 10000, CONSENSUS_TIMEOUT, MAX_DATA_AGE); // 100%
        // Register 4 nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node3, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node4, 2 ether);
        
        // Submit proofs with tie (2 valid, 2 invalid)
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        vm.prank(node2);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        vm.prank(node3);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, false);
        vm.prank(node4);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, false);
        
        // Check consensus data
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, bool isFinalized, bool finalResult, , ) = oracle.getConsensusData(dataId);
        
        assertEq(validVotes, 2);
        assertEq(invalidVotes, 2);
        assertEq(totalVotes, 4);
        // With 100% threshold and owner included in nodeList, requiredVotes = 5, so not finalized
        assertFalse(isFinalized);
        assertFalse(finalResult);
    }
    
    function testConsensusWithMoreInvalidVotes() public {
        // Register 3 nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node3, 2 ether);
        
        // Submit proofs with more invalid votes
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        vm.prank(node2);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, false);
        vm.prank(node3);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, false);
        
        // Check consensus data
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, bool isFinalized, bool finalResult, , ) = oracle.getConsensusData(dataId);
        
        assertEq(validVotes, 1);
        assertEq(invalidVotes, 2);
        assertEq(totalVotes, 3);
        assertTrue(isFinalized);
        assertFalse(finalResult); // More invalid votes should result in false
    }
    
    function testEmergencyFinalizeInvalidDataId() public {
        bytes32 invalidDataId = keccak256("invalid");
        
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.InvalidDataId.selector);
        oracle.emergencyFinalize(invalidDataId, true);
    }
    
    function testUpdateNodeReputationNotRegistered() public {
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.NodeNotRegistered.selector);
        oracle.updateNodeReputation(node1, 1500);
    }
    
    function testSetNodeActiveNotRegistered() public {
        vm.prank(owner);
        vm.expectRevert(Ed25519Oracle.NodeNotRegistered.selector);
        oracle.setNodeActive(node1, false);
    }
    
    function testUpdateParametersOnlyOwner() public {
        vm.prank(node1);
        vm.expectRevert();
        oracle.updateParameters(2 ether, 6000, 600, 7200);
    }
    
    function testUpdateNodeReputationOnlyOwner() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        vm.prank(node1);
        vm.expectRevert();
        oracle.updateNodeReputation(node1, 1500);
    }
    
    function testSetNodeActiveOnlyOwner() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        vm.prank(node1);
        vm.expectRevert();
        oracle.setNodeActive(node1, false);
    }
    
    function testEmergencyFinalizeOnlyOwner() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        vm.prank(node1);
        vm.expectRevert();
        oracle.emergencyFinalize(keccak256("test"), true);
    }
    
    function testUnregisterNodeOnlyOwner() public {
        // Register node first
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        vm.prank(node1);
        vm.expectRevert();
        oracle.unregisterNode(node1);
    }
    
    function testRegisterNodeOnlyOwner() public {
        vm.prank(node1);
        vm.expectRevert();
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
    }
    
    function testGetFinalizedResult() public {
        // Register nodes and reach consensus
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        vm.prank(node2);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        assertTrue(oracle.isVerified(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
    }
    
    function testGetFinalizedResultNotFinalized() public {
        assertFalse(oracle.isVerified(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
    }
    
    function testReceiveFunction() public {
        uint256 initialBalance = address(oracle).balance;
        
        // Send ETH to contract
        (bool success, ) = address(oracle).call{value: 1 ether}("");
        assertTrue(success);
        
        assertEq(address(oracle).balance, initialBalance + 1 ether);
    }
    
    function testConsensusWithOwnerZeroStake() public {
        // Register one node (owner has 0 stake)
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        
        // Submit proof from owner (should not count towards consensus)
        vm.prank(owner);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Submit proof from node1
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        // Check consensus data - should not be finalized as only 1 active staked node
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, bool isFinalized, bool finalResult, , ) = oracle.getConsensusData(dataId);
        
        assertEq(validVotes, 2); // Owner + node1
        assertEq(invalidVotes, 0);
        assertEq(totalVotes, 2);
        assertFalse(isFinalized); // Should not be finalized as only 1 active staked node
        assertFalse(finalResult);
    }
    
    function testConsensusThresholdEdgeCases() public {
        // Test with 100% threshold; register 3 nodes but only 2 vote
        vm.prank(owner);
        oracle.updateParameters(1 ether, 10000, 300, 3600); // 100% threshold
        
        // Register 3 nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node3, 2 ether);
        
        // Submit proofs - should not reach consensus due to high threshold
        vm.prank(node1);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        vm.prank(node2);
        oracle.submitProof(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        bytes32 dataId = keccak256(abi.encodePacked(TEST_PUBLIC_KEY, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        (uint256 validVotes, uint256 invalidVotes, uint256 totalVotes, bool isFinalized, bool finalResult, , ) = oracle.getConsensusData(dataId);
        
        assertEq(validVotes, 2);
        assertEq(invalidVotes, 0);
        assertEq(totalVotes, 2);
        assertFalse(isFinalized); // Should not be finalized due to high threshold
        assertFalse(finalResult);
    }
    
    function testMultipleDataIds() public {
        // Register nodes
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node1, 2 ether);
        vm.prank(owner);
        oracle.registerNode{value: 2 ether}(node2, 2 ether);
        
        // Submit proofs for different data
        bytes32 publicKey1 = 0x1111111111111111111111111111111111111111111111111111111111111111;
        bytes32 publicKey2 = 0x2222222222222222222222222222222222222222222222222222222222222222;
        
        vm.prank(node1);
        oracle.submitProof(publicKey1, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        vm.prank(node2);
        oracle.submitProof(publicKey1, TEST_MESSAGE_HASH, TEST_SIGNATURE, true);
        
        vm.prank(node1);
        oracle.submitProof(publicKey2, TEST_MESSAGE_HASH, TEST_SIGNATURE, false);
        vm.prank(node2);
        oracle.submitProof(publicKey2, TEST_MESSAGE_HASH, TEST_SIGNATURE, false);
        
        // Check both data IDs
        bytes32 dataId1 = keccak256(abi.encodePacked(publicKey1, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        bytes32 dataId2 = keccak256(abi.encodePacked(publicKey2, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        
        assertTrue(oracle.isVerified(publicKey1, TEST_MESSAGE_HASH, TEST_SIGNATURE));
        assertFalse(oracle.isVerified(publicKey2, TEST_MESSAGE_HASH, TEST_SIGNATURE));
    }
}
