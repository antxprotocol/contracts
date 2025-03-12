// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {CompleteMerkle} from "@murky/CompleteMerkle.sol";
import "./interfaces/ISettlement.sol";
import "./interfaces/IAsset.sol";

contract SettlementForTest is Ownable, ISettlement {
    uint256 public batchId;
    address public assetContract;
    mapping(address => bool) public isBatchSubmitter;
    address[] private batchSubmitterList;
    mapping(uint256 => ISettlement.SettlementItem) public orders;
    mapping(uint256 => ISettlement.Batch) public batches;
    CompleteMerkle private immutable merkle;

    error NotBatchSubmitter();
    error InvalidBatchSubmitter();
    error InvalidAssetContract();
    error InvalidStartBlock();
    error InvalidTotalItems();
    error InvalidRootHash();
    error InvalidBatchId();
    error OrderAlreadyExists();
    error MismatchRootHash();
    error ErrInvalidProof();

    modifier onlyBatchSubmitter() {
        if (!isBatchSubmitter[msg.sender]) revert NotBatchSubmitter();
        _;
    }

    constructor(address _assetContract, address[] memory _batchSubmitter) Ownable(msg.sender) {
        if (_assetContract == address(0)) revert InvalidAssetContract();
        assetContract = _assetContract;
        emit AssetContractUpdated(_assetContract);

        _updateBatchSubmitters(_batchSubmitter);
        
        merkle = new CompleteMerkle();
    }

    function getBatchSubmitter() external view returns (address[] memory) {
        return batchSubmitterList;
    }

    function _updateBatchSubmitters(address[] memory _batchSubmitter) private {
        if (_batchSubmitter.length == 0) revert InvalidBatchSubmitter();
        
        uint256 currentLength = batchSubmitterList.length;
        for (uint256 i = 0; i < currentLength; i++) {
            isBatchSubmitter[batchSubmitterList[i]] = false;
        }
        
        uint256 newLength = _batchSubmitter.length;
        for (uint256 i = 0; i < newLength; i++) {
            isBatchSubmitter[_batchSubmitter[i]] = true;
        }
        
        batchSubmitterList = _batchSubmitter;
        emit BatchSubmitterUpdated(_batchSubmitter);
    }

    function setBatchSubmitter(address[] calldata _batchSubmitter) external onlyOwner {
        _updateBatchSubmitters(_batchSubmitter);
    }

    function getAssetContract() external view returns (address) {
        return assetContract;
    }

    function setAssetContract(address _assetContract) external onlyOwner {
        if (_assetContract == address(0)) revert InvalidAssetContract();
        assetContract = _assetContract;
        emit AssetContractUpdated(_assetContract);
    }

    function submitBatch(uint256 _startBlock, uint256 _totalItems, bytes32 _rootHash) external onlyBatchSubmitter {
        if (_startBlock == 0) revert InvalidStartBlock();
        if (_totalItems == 0 || _totalItems >= 10000) revert InvalidTotalItems();
        if (_rootHash == bytes32(0)) revert InvalidRootHash();
        
        bytes32 previousRootHash = bytes32(0);
        uint256 currentBatchId = batchId; // Cache state variable
        
        if (currentBatchId > 0) {
            ISettlement.Batch storage previousBatch = batches[currentBatchId]; 
            previousRootHash = previousBatch.rootHash;
            if (_startBlock != previousBatch.startBlock + previousBatch.totalItems) revert InvalidStartBlock();
        }

        // Increment batchId and cache new value
        uint256 newBatchId = currentBatchId + 1;
        batchId = newBatchId;

        // Store directly to state variable, skip temporary memory struct
        ISettlement.Batch storage newBatch = batches[newBatchId];
        newBatch.startBlock = _startBlock;
        newBatch.totalItems = _totalItems;
        newBatch.rootHash = _rootHash;
        newBatch.previousRootHash = previousRootHash;
        
        emit BatchSubmitted(newBatchId, _startBlock, _totalItems, _rootHash, previousRootHash);
    }

    function getBatch(uint256 _batchId) public view returns (ISettlement.Batch memory) {
        return batches[_batchId];
    }

    function finalizeSettlement(uint256 _batchId, ISettlement.SettlementItem[] calldata _items) external {
        // Verify batchId is valid
        ISettlement.Batch storage existBatch = batches[_batchId]; // Use storage pointer instead of memory copy
        if (existBatch.rootHash == bytes32(0)) revert InvalidBatchId();

        // Optimization: calculate items length once
        uint256 itemsLength = _items.length;
        
        // Pre-allocate memory to reduce dynamic allocation
        bytes32[] memory leaves = new bytes32[](itemsLength);
        
        // First fill the leaves array and optimize validation logic
        for (uint256 i = 0; i < itemsLength; i++) {
            ISettlement.SettlementItem calldata item = _items[i];
            
            // Verify order doesn't exist and store new order
            if (orders[item.orderId].orderId != 0 || orders[item.orderId].businessOrderId != 0) {
                revert OrderAlreadyExists();
            }
            
            // Calculate leaf node hash
            leaves[i] = generateLeaf(_batchId, item);
        }

        // Calculate batch root hash
        bytes32 batchRootHash = merkle.getRoot(leaves);
        
        // Calculate final root hash and verify
        bytes32 finalRootHash = generateFinalRootHash(batchRootHash, existBatch.previousRootHash);
        
        if (finalRootHash != existBatch.rootHash) {
            revert MismatchRootHash();
        }

        // Cache assetContract to reduce storage reads
        address assetContractCache = assetContract;
        
        // Process each settlement item
        for (uint256 i = 0; i < itemsLength; i++) {
            ISettlement.SettlementItem calldata item = _items[i];
            
            // Store order information
            orders[item.orderId] = item;

            // Verify Merkle proof
            bytes32[] memory proof = merkle.getProof(leaves, i);
            if (!merkle.verifyProof(batchRootHash, proof, leaves[i])) {
                revert ErrInvalidProof();
            }

            // Update asset contract
            if (item.isAdd) {
                IAsset(assetContractCache).addUserBalance(item.user, item.amount);
            } else if (item.isSettleFee) {
                IAsset(assetContractCache).addFeeBalance(item.amount);
            } else {
                IAsset(assetContractCache).subUserBalance(item.user, item.amount);
            }

            emit Settlement(item.orderId, item.businessOrderId, item.user, item.amount, item.isAdd, item.isSettleFee);
        }
    }

    // Inline generateLeaf function to finalizeSettlement to reduce function call overhead
    function generateLeaf(uint256 _batchId, ISettlement.SettlementItem calldata item) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                _batchId, item.orderId, item.businessOrderId, item.user, item.amount, item.isAdd, item.isSettleFee
            )
        );
    }

    // Inline generateFinalRootHash to finalizeSettlement to reduce function call overhead
    function generateFinalRootHash(bytes32 batchRootHash, bytes32 previousRootHash) public view returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = batchRootHash;
        leaves[1] = previousRootHash;
        return merkle.getRoot(leaves);
    }

     // for test
    function addUserBalanceForTest(address user, uint256 amount) public onlyOwner {
        IAsset(assetContract).addUserBalance(user, amount);
    }

    function addFeeBalanceForTest(uint256 amount) public onlyOwner {
        IAsset(assetContract).addFeeBalance(amount);
    }

    function subUserBalanceForTest(address user, uint256 amount) public onlyOwner {
        IAsset(assetContract).subUserBalance(user, amount);
    }
}

