// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {CompleteMerkle} from "@murky/CompleteMerkle.sol";
import "./interfaces/ISettlement.sol";
import "./interfaces/IAsset.sol";

contract Settlement is Ownable, ReentrancyGuard, Pausable, ISettlement {
    uint256 public lastBatchId; 
    address public assetContract;
    mapping(uint256 => ISettlement.Batch) public batches;
    mapping(address => bool) public operators;
    bytes32 public rootHash;
    CompleteMerkle private immutable merkle;
    
    // Constants for security limits
    uint256 public constant MAX_BATCH_SIZE = 1000; // Maximum items in a batch
    uint256 public constant SETTLEMENT_TIME_LOCK = 180 seconds; 

    modifier validAddress(address addr) {
        if (addr == address(0)) revert ZeroAddressNotAllowed();
        _;
    }

    modifier onlyOperator() {
        if (!isOperator(msg.sender)) revert NotOperator();
        _;
    }

    constructor(address _assetContract, address[] memory _operators) Ownable(msg.sender) {
        if (_assetContract == address(0)) revert ZeroAddressNotAllowed();
        assetContract = _assetContract;
        emit AssetContractUpdated(_assetContract);

        for (uint256 i = 0; i < _operators.length; i++) {
            operators[_operators[i]] = true;
            emit LogOperatorAdded(_operators[i]);
        }
        
        merkle = new CompleteMerkle();
    }

    function registerOperator(address newOperator) external onlyOwner validAddress(newOperator) {
        operators[newOperator] = true;
        emit LogOperatorAdded(newOperator);
    }

    function unregisterOperator(address removedOperator) external onlyOwner validAddress(removedOperator) {
        operators[removedOperator] = false;
        emit LogOperatorRemoved(removedOperator);
    }

    function setAssetContract(address _assetContract) external onlyOwner validAddress(_assetContract) whenNotPaused {
        assetContract = _assetContract;
        emit AssetContractUpdated(_assetContract);
    }

    // Pause and unpause functions for emergency stops
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function isOperator(address testedOperator) public view returns (bool) {
        return operators[testedOperator];
    }

    function submitBatch(uint256 _startBlock,uint256 _endBlock, uint256 _totalItems, bytes32 _rootHash) 
        external 
        onlyOperator 
        whenNotPaused 
    {
        if (_startBlock == 0) revert InvalidStartBlock();
        if (_totalItems == 0) revert InvalidTotalItems();
        if (_totalItems > MAX_BATCH_SIZE) revert BatchTooLarge();
        if (_rootHash == bytes32(0)) revert InvalidRootHash();
        if (_startBlock >= _endBlock) revert InvalidStartBlock();
        
        bytes32 previousRootHash = bytes32(0);
        uint256 currentBatchId = lastBatchId;
        
        if (currentBatchId > 0) {
            ISettlement.Batch storage previousBatch = batches[currentBatchId];
            previousRootHash = previousBatch.rootHash;
            if (_startBlock != previousBatch.endBlock + 1) revert InvalidStartBlock();
        }

        uint256 newBatchId = currentBatchId + 1;
        lastBatchId = newBatchId;

        ISettlement.Batch storage newBatch = batches[newBatchId];
        newBatch.startBlock = _startBlock;
        newBatch.endBlock = _endBlock;
        newBatch.totalItems = _totalItems;
        newBatch.rootHash = _rootHash;
        newBatch.previousRootHash = previousRootHash;
        newBatch.batchTime = block.timestamp;
        
        emit BatchSubmitted(newBatchId, _startBlock,_endBlock, _totalItems, _rootHash, previousRootHash);

        // set last batch time
        IAsset(assetContract).setLastBatchTime(block.timestamp);
    }

    function getBatch(uint256 _batchId) public view returns (ISettlement.Batch memory) {
        return batches[_batchId];
    }

    function finalizeSettlement(uint256 _batchId, ISettlement.SettlementItem[] calldata _items) 
        external 
        onlyOperator 
        nonReentrant 
        whenNotPaused 
    {
        // Check batch size limit for gas efficiency
        uint256 itemsLength = _items.length;
        if (itemsLength == 0) revert EmptyArrayNotAllowed();
        
        // Verify lastBatchId is valid
        ISettlement.Batch storage existBatch = batches[_batchId];
        if (existBatch.rootHash == bytes32(0)) revert InvalidRootHash();
        if (block.timestamp < existBatch.batchTime + SETTLEMENT_TIME_LOCK) revert TimeLockNotPassed();
        if (existBatch.finalized) revert BatchAlreadyFinalized();
        if (itemsLength != existBatch.totalItems) revert InvalidTotalItems();
        
        // Pre-allocate memory for leaves array
        bytes32[] memory leaves = new bytes32[](itemsLength);
        
        // First, validate all items and build leaves array
        for (uint256 i = 0; i < itemsLength; i++) {
            ISettlement.SettlementItem calldata item = _items[i];
            
            // Verify item has valid user address, except for trade fee in, risk margin in, risk margin out
            if (item.user == address(0) && 
            (item.types != SettlementType.TradeFeeIn ||
                 item.types != SettlementType.RiskMarginIn || 
                 item.types != SettlementType.RiskMarginOut)) revert ZeroAddressNotAllowed();
            
            // Calculate leaf node hash
            leaves[i] = generateLeaf(_batchId, item);
        }

        // Calculate and verify Merkle root
        bytes32 batchRootHash = merkle.getRoot(leaves);
        bytes32 finalRootHash = generateFinalRootHash(batchRootHash, existBatch.previousRootHash);
        
        if (finalRootHash != existBatch.rootHash) {
            revert MismatchRootHash();
        }

        // Cache assetContract to save gas
        address assetContractCache = assetContract;
        
        // Process each settlement item after verification
        for (uint256 i = 0; i < itemsLength; i++) {
            ISettlement.SettlementItem calldata item = _items[i];
            
            // Verify Merkle proof first before storing or processing
            bytes32[] memory proof = merkle.getProof(leaves, i);
            if (!merkle.verifyProof(batchRootHash, proof, leaves[i])) {
                revert ErrInvalidProof();
            }
            
            // Update asset contract
            if (item.types == SettlementType.Deposit || item.types == SettlementType.TransferIn){
                IAsset(assetContractCache).addUserBalance(item.user, item.amount);
            } else if (item.types == SettlementType.TradeFeeOut || item.types == SettlementType.TransferOut || item.types == SettlementType.Liquidation) {
                IAsset(assetContractCache).subUserBalance(item.user, item.amount);
            } else if (item.types == SettlementType.TradeFeeIn) {
                IAsset(assetContractCache).addFeeBalance(item.amount);
            } else if (item.types == SettlementType.Withdraw) {
                IAsset(assetContractCache).userWithdraw(item.user, item.amount);
            } else if (item.types == SettlementType.ForceWithdraw) {
                IAsset(assetContractCache).acceptForceWithdrawal(item.user, item.amount);
            } else if (item.types == SettlementType.Liquidation) {
                IAsset(assetContractCache).subUserBalance(item.user, item.amount);
            } else if (item.types == SettlementType.RiskMarginIn) {
                IAsset(assetContractCache).addRiskMarginBalance(item.amount);
            } else if (item.types == SettlementType.RiskMarginOut) {
                IAsset(assetContractCache).subRiskMarginBalance(item.amount);
            }

            emit Settlement(item.orderId, item.businessOrderId, item.user, item.amount, item.types);
        }

        // Mark batch as finalized
        existBatch.finalized = true;
    }

    function generateLeaf(uint256 _batchId, ISettlement.SettlementItem calldata item) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                _batchId, item.orderId, item.businessOrderId, item.user, item.amount, item.types
            )
        );
    }

    function generateFinalRootHash(bytes32 batchRootHash, bytes32 previousRootHash) public view returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = batchRootHash;
        leaves[1] = previousRootHash;
        return merkle.getRoot(leaves);
    }

    // Test functions
    function addFeeBalanceForTest(uint256 amount) external {
        IAsset(assetContract).addFeeBalance(amount);
    }

    function setLastBatchTimeForTest(uint256 time) external {
        IAsset(assetContract).setLastBatchTime(time);
    }
}
