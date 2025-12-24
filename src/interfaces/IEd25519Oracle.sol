// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IEd25519Oracle
 * @dev Interface for Ed25519 Oracle system
 */
interface IEd25519Oracle {
    // ============ Events ============

    event NodeRegistered(address indexed node, uint256 stake);
    event NodeUnregistered(address indexed node);
    event NodeStakeUpdated(address indexed node, uint256 newStake);
    event ProofSubmitted(bytes32 indexed dataId, address indexed node, bool isValid);
    event ConsensusReached(bytes32 indexed dataId, bool result, uint256 validVotes, uint256 totalVotes);
    event DataExpired(bytes32 indexed dataId);
    event ParametersUpdated(
        uint256 minimumStake, uint256 consensusThreshold, uint256 consensusTimeout, uint256 maxDataAge
    );

    // ============ Node Management ============

    /**
     * @dev Register a new node
     * @param nodeAddress Address of the node to register
     * @param stakeAmount Initial stake amount
     */
    function registerNode(address nodeAddress, uint256 stakeAmount) external payable;

    /**
     * @dev Unregister a node
     * @param nodeAddress Address of the node to unregister
     */
    function unregisterNode(address nodeAddress) external;

    /**
     * @dev Update node stake
     * @param newStake New stake amount
     */
    function updateStake(uint256 newStake) external payable;

    // ============ Proof Submission ============

    /**
     * @dev Submit proof data for signature verification
     * @param publicKey Ed25519 public key
     * @param messageHash Hash of the message
     * @param signature Ed25519 signature
     * @param isValid Whether the signature is valid according to this node
     */
    function submitProof(bytes32 publicKey, bytes32 messageHash, bytes calldata signature, bool isValid) external;

    // ============ Query Functions ============

    /**
     * @dev Check if a signature is verified by consensus
     * @param publicKey Ed25519 public key
     * @param messageHash Hash of the message
     * @param signature Ed25519 signature
     * @return bool Whether the signature is verified
     */
    function isVerified(bytes32 publicKey, bytes32 messageHash, bytes calldata signature) external view returns (bool);

    /**
     * @dev Get consensus data for a specific data ID
     * @param dataId Unique identifier for the data
     * @return validVotes Number of valid votes
     * @return invalidVotes Number of invalid votes
     * @return totalVotes Total number of votes
     * @return isFinalized Whether consensus has been reached
     * @return finalResult Final consensus result
     * @return createdAt When this data was first submitted
     * @return finalizedAt When consensus was reached
     */
    function getConsensusData(bytes32 dataId)
        external
        view
        returns (
            uint256 validVotes,
            uint256 invalidVotes,
            uint256 totalVotes,
            bool isFinalized,
            bool finalResult,
            uint256 createdAt,
            uint256 finalizedAt
        );

    /**
     * @dev Get node information
     * @param nodeAddress Address of the node
     * @return isActive Whether the node is active
     * @return stake Node's stake amount
     * @return reputation Node's reputation score
     * @return lastActivity Last time node was active
     * @return isRegistered Whether node is registered
     */
    function getNodeInfo(address nodeAddress)
        external
        view
        returns (bool isActive, uint256 stake, uint256 reputation, uint256 lastActivity, bool isRegistered);

    /**
     * @dev Get all registered nodes
     * @return Array of node addresses
     */
    function getAllNodes() external view returns (address[] memory);

    /**
     * @dev Get oracle statistics
     * @return totalNodes Total number of registered nodes
     * @return totalStakeAmount Total stake amount
     * @return minStake Minimum stake required
     * @return consensusThresh Consensus threshold (in basis points)
     * @return consensusTime Consensus timeout in seconds
     * @return maxAge Maximum data age in seconds
     */
    function getOracleStats()
        external
        view
        returns (
            uint256 totalNodes,
            uint256 totalStakeAmount,
            uint256 minStake,
            uint256 consensusThresh,
            uint256 consensusTime,
            uint256 maxAge
        );

    // ============ Admin Functions ============

    /**
     * @dev Update oracle parameters
     * @param _minimumStake Minimum stake required for nodes
     * @param _consensusThreshold Consensus threshold (in basis points)
     * @param _consensusTimeout Consensus timeout in seconds
     * @param _maxDataAge Maximum data age in seconds
     */
    function updateParameters(
        uint256 _minimumStake,
        uint256 _consensusThreshold,
        uint256 _consensusTimeout,
        uint256 _maxDataAge
    ) external;

    /**
     * @dev Update node reputation
     * @param nodeAddress Address of the node
     * @param newReputation New reputation score
     */
    function updateNodeReputation(address nodeAddress, uint256 newReputation) external;

    /**
     * @dev Activate/deactivate a node
     * @param nodeAddress Address of the node
     * @param active Whether to activate the node
     */
    function setNodeActive(address nodeAddress, bool active) external;

    /**
     * @dev Emergency function to finalize consensus manually
     * @param dataId Unique identifier for the data
     * @param result Consensus result
     */
    function emergencyFinalize(bytes32 dataId, bool result) external;
}
