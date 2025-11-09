// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IEd25519Oracle} from "../interfaces/IEd25519Oracle.sol";

/**
 * @title Ed25519Oracle
 * @dev A decentralized oracle system for Ed25519 signature verification
 * @notice This oracle allows multiple nodes to submit proof data and reach consensus on signature validity
 */
contract Ed25519Oracle is Ownable, ReentrancyGuard, IEd25519Oracle {
    // ============ Structs ============
    
    // Removed ProofData struct as it's not used in the current implementation
    
    struct ConsensusData {
        bytes32 dataId;         // Unique identifier for this data
        mapping(address => bool) nodeVotes;  // Votes from each node
        uint256 validVotes;     // Number of valid votes
        uint256 invalidVotes;   // Number of invalid votes
        uint256 totalVotes;     // Total number of votes
        bool isFinalized;       // Whether consensus has been reached
        bool finalResult;       // Final consensus result
        uint256 createdAt;      // When this data was first submitted
        uint256 finalizedAt;    // When consensus was reached
    }
    
    struct NodeInfo {
        address nodeAddress;    // Node's address
        bool isActive;          // Whether the node is active
        uint256 stake;          // Node's stake amount
        uint256 reputation;     // Node's reputation score
        uint256 lastActivity;   // Last time node was active
        bool isRegistered;      // Whether node is registered
    }
    
    // ============ State Variables ============
    
    mapping(bytes32 => ConsensusData) public consensusData;
    mapping(address => NodeInfo) public nodes;
    mapping(bytes32 => bool) public finalizedResults;
    
    address[] public nodeList;
    uint256 public totalStake;
    uint256 public minimumStake;
    uint256 public consensusThreshold;  // Percentage of nodes needed for consensus (in basis points)
    uint256 public consensusTimeout;    // Time in seconds before consensus expires
    uint256 public maxDataAge;          // Maximum age of data before it expires
    
    // ============ Events ============
    // Events are defined in the interface, no need to redeclare them here
    
    // ============ Errors ============
    
    error NodeNotRegistered();
    error NodeAlreadyRegistered();
    error InsufficientStake();
    error ConsensusAlreadyFinalized();
    error ConsensusNotReached();
    error DataExpiredError();
    error InvalidDataId();
    error OnlyActiveNode();
    error InvalidConsensusThreshold();
    error InvalidTimeout();
    
    // ============ Modifiers ============
    
    modifier onlyRegisteredNode() {
        if (!nodes[msg.sender].isRegistered) revert NodeNotRegistered();
        _;
    }
    
    modifier onlyActiveNode() {
        if (!nodes[msg.sender].isActive) revert OnlyActiveNode();
        _;
    }
    
    // ============ Constructor ============
    
    constructor(
        uint256 _minimumStake,
        uint256 _consensusThreshold,
        uint256 _consensusTimeout,
        uint256 _maxDataAge
    ) Ownable(msg.sender) {
        minimumStake = _minimumStake;
        consensusThreshold = _consensusThreshold;
        consensusTimeout = _consensusTimeout;
        maxDataAge = _maxDataAge;
        
        // Register owner as initial node
        _registerNode(msg.sender, 0);
    }
    
    // ============ Node Management ============
    
    /**
     * @dev Register a new node
     * @param nodeAddress Address of the node to register
     * @param stakeAmount Initial stake amount
     */
    function registerNode(address nodeAddress, uint256 stakeAmount) external payable onlyOwner {
        if (nodes[nodeAddress].isRegistered) revert NodeAlreadyRegistered();
        if (stakeAmount < minimumStake) revert InsufficientStake();
        
        _registerNode(nodeAddress, stakeAmount);
        
        if (stakeAmount > 0) {
            // Transfer stake to contract
            payable(address(this)).transfer(stakeAmount);
        }
    }
    
    /**
     * @dev Internal function to register a node
     */
    function _registerNode(address nodeAddress, uint256 stakeAmount) internal {
        nodes[nodeAddress] = NodeInfo({
            nodeAddress: nodeAddress,
            isActive: true,
            stake: stakeAmount,
            reputation: 1000, // Initial reputation
            lastActivity: block.timestamp,
            isRegistered: true
        });
        
        nodeList.push(nodeAddress);
        totalStake += stakeAmount;
        
        emit NodeRegistered(nodeAddress, stakeAmount);
    }
    
    /**
     * @dev Unregister a node (only owner)
     */
    function unregisterNode(address nodeAddress) external onlyOwner {
        if (!nodes[nodeAddress].isRegistered) revert NodeNotRegistered();
        
        NodeInfo storage node = nodes[nodeAddress];
        node.isActive = false;
        node.isRegistered = false;
        
        // Remove from node list
        for (uint256 i = 0; i < nodeList.length; i++) {
            if (nodeList[i] == nodeAddress) {
                nodeList[i] = nodeList[nodeList.length - 1];
                nodeList.pop();
                break;
            }
        }
        
        totalStake -= node.stake;
        
        // Return stake to node
        if (node.stake > 0) {
            payable(nodeAddress).transfer(node.stake);
        }
        
        emit NodeUnregistered(nodeAddress);
    }
    
    /**
     * @dev Update node stake
     */
    function updateStake(uint256 newStake) external payable onlyRegisteredNode {
        NodeInfo storage node = nodes[msg.sender];
        
        if (newStake < minimumStake) revert InsufficientStake();
        
        uint256 oldStake = node.stake;
        node.stake = newStake;
        totalStake = totalStake - oldStake + newStake;
        
        // Handle stake difference
        if (newStake > oldStake) {
            // Add more stake
            payable(address(this)).transfer(newStake - oldStake);
        } else if (newStake < oldStake) {
            // Return excess stake
            payable(msg.sender).transfer(oldStake - newStake);
        }
        
        emit NodeStakeUpdated(msg.sender, newStake);
    }
    
    // ============ Proof Submission ============
    
    /**
     * @dev Submit proof data for signature verification
     * @param publicKey Ed25519 public key
     * @param messageHash Hash of the message
     * @param signature Ed25519 signature
     * @param isValid Whether the signature is valid according to this node
     */
    function submitProof(
        bytes32 publicKey,
        bytes32 messageHash,
        bytes calldata signature,
        bool isValid
    ) external onlyActiveNode nonReentrant {
        bytes32 dataId = keccak256(abi.encodePacked(publicKey, messageHash, signature));
        
        // Check if data has expired
        if (consensusData[dataId].createdAt > 0) {
            if (block.timestamp - consensusData[dataId].createdAt > maxDataAge) {
                revert DataExpiredError();
            }
        }
        
        // Initialize consensus data if first submission
        if (consensusData[dataId].createdAt == 0) {
            consensusData[dataId].createdAt = block.timestamp;
        }
        
        // Check if already voted
        if (consensusData[dataId].nodeVotes[msg.sender]) {
            // Even if already voted, check for timeout
            _checkConsensus(dataId);
            return; // Already voted, ignore
        }
        
        // Record vote
        consensusData[dataId].nodeVotes[msg.sender] = true;
        consensusData[dataId].totalVotes++;
        
        if (isValid) {
            consensusData[dataId].validVotes++;
        } else {
            consensusData[dataId].invalidVotes++;
        }
        
        // Update node activity
        nodes[msg.sender].lastActivity = block.timestamp;
        
        emit ProofSubmitted(dataId, msg.sender, isValid);
        
        // Check for consensus
        _checkConsensus(dataId);
    }
    
    /**
     * @dev Check if consensus has been reached
     */
    function _checkConsensus(bytes32 dataId) internal {
        ConsensusData storage data = consensusData[dataId];
        
        if (data.isFinalized) return;
        
        // Check for timeout first
        if (block.timestamp - data.createdAt > consensusTimeout) {
            data.isFinalized = true;
            data.finalResult = false; // Default to invalid on timeout
            data.finalizedAt = block.timestamp;
            
            finalizedResults[dataId] = false;
            
            emit DataExpired(dataId);
            return;
        }
        
        // Check if we have enough votes for consensus
        uint256 requiredVotes = (nodeList.length * consensusThreshold) / 10000;
        
        // Require at least 2 active nodes for consensus (excluding owner with 0 stake)
        uint256 activeNodes = 0;
        for (uint256 i = 0; i < nodeList.length; i++) {
            if (nodes[nodeList[i]].isActive && nodes[nodeList[i]].stake > 0) {
                activeNodes++;
            }
        }
        
        if (activeNodes < 2) {
            return; // No consensus possible with less than 2 active staked nodes
        }
        
        // Ensure minimum required votes
        if (requiredVotes == 0) {
            requiredVotes = 2; // At least 2 votes required for consensus
        }
        
        if (data.totalVotes >= requiredVotes) {
            // Determine consensus result
            bool consensusResult = data.validVotes > data.invalidVotes;
            
            // Finalize consensus
            data.isFinalized = true;
            data.finalResult = consensusResult;
            data.finalizedAt = block.timestamp;
            
            // Store final result
            finalizedResults[dataId] = consensusResult;
            
            emit ConsensusReached(dataId, consensusResult, data.validVotes, data.totalVotes);
        }
    }
    
    // ============ Query Functions ============
    
    /**
     * @dev Check if a signature is verified by consensus
     * @param publicKey Ed25519 public key
     * @param messageHash Hash of the message
     * @param signature Ed25519 signature
     * @return bool Whether the signature is verified
     */
    function isVerified(
        bytes32 publicKey,
        bytes32 messageHash,
        bytes calldata signature
    ) external view override(IEd25519Oracle) returns (bool) {
        bytes32 dataId = keccak256(abi.encodePacked(publicKey, messageHash, signature));
        return finalizedResults[dataId];
    }
    
    /**
     * @dev Get consensus data for a specific data ID
     */
    function getConsensusData(bytes32 dataId) external view returns (
        uint256 validVotes,
        uint256 invalidVotes,
        uint256 totalVotes,
        bool isFinalized,
        bool finalResult,
        uint256 createdAt,
        uint256 finalizedAt
    ) {
        ConsensusData storage data = consensusData[dataId];
        return (
            data.validVotes,
            data.invalidVotes,
            data.totalVotes,
            data.isFinalized,
            data.finalResult,
            data.createdAt,
            data.finalizedAt
        );
    }
    
    /**
     * @dev Get node information
     */
    function getNodeInfo(address nodeAddress) external view returns (
        bool isActive,
        uint256 stake,
        uint256 reputation,
        uint256 lastActivity,
        bool isRegistered
    ) {
        NodeInfo storage node = nodes[nodeAddress];
        return (
            node.isActive,
            node.stake,
            node.reputation,
            node.lastActivity,
            node.isRegistered
        );
    }
    
    /**
     * @dev Get all registered nodes
     */
    function getAllNodes() external view returns (address[] memory) {
        return nodeList;
    }
    
    /**
     * @dev Get oracle statistics
     */
    function getOracleStats() external view returns (
        uint256 totalNodes,
        uint256 totalStakeAmount,
        uint256 minStake,
        uint256 consensusThresh,
        uint256 consensusTime,
        uint256 maxAge
    ) {
        return (
            nodeList.length,
            totalStake,
            minimumStake,
            consensusThreshold,
            consensusTimeout,
            maxDataAge
        );
    }
    
    // ============ Admin Functions ============
    
    /**
     * @dev Update oracle parameters
     */
    function updateParameters(
        uint256 _minimumStake,
        uint256 _consensusThreshold,
        uint256 _consensusTimeout,
        uint256 _maxDataAge
    ) external onlyOwner {
        if (_consensusThreshold > 10000) revert InvalidConsensusThreshold();
        if (_consensusTimeout == 0) revert InvalidTimeout();
        
        minimumStake = _minimumStake;
        consensusThreshold = _consensusThreshold;
        consensusTimeout = _consensusTimeout;
        maxDataAge = _maxDataAge;
        
        emit ParametersUpdated(_minimumStake, _consensusThreshold, _consensusTimeout, _maxDataAge);
    }
    
    /**
     * @dev Update node reputation (admin only)
     */
    function updateNodeReputation(address nodeAddress, uint256 newReputation) external onlyOwner {
        if (!nodes[nodeAddress].isRegistered) revert NodeNotRegistered();
        nodes[nodeAddress].reputation = newReputation;
    }
    
    /**
     * @dev Activate/deactivate a node
     */
    function setNodeActive(address nodeAddress, bool active) external onlyOwner {
        if (!nodes[nodeAddress].isRegistered) revert NodeNotRegistered();
        nodes[nodeAddress].isActive = active;
    }
    
    /**
     * @dev Emergency function to finalize consensus manually
     */
    function emergencyFinalize(bytes32 dataId, bool result) external onlyOwner {
        ConsensusData storage data = consensusData[dataId];
        if (data.createdAt == 0) revert InvalidDataId();
        
        data.isFinalized = true;
        data.finalResult = result;
        data.finalizedAt = block.timestamp;
        
        finalizedResults[dataId] = result;
        
        emit ConsensusReached(dataId, result, data.validVotes, data.totalVotes);
    }
    
    // ============ Fallback ============
    
    receive() external payable {
        // Allow contract to receive ETH for staking
    }
}
