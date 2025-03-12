// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {CompleteMerkle} from "@murky/CompleteMerkle.sol";
import "./interfaces/ISettlement.sol";
import "./interfaces/IAsset.sol";

contract Settlement is Ownable, ISettlement {
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
        uint256 currentBatchId = batchId;
        
        if (currentBatchId > 0) {
            ISettlement.Batch storage previousBatch = batches[currentBatchId];
            previousRootHash = previousBatch.rootHash;
            if (_startBlock != previousBatch.startBlock + previousBatch.totalItems) revert InvalidStartBlock();
        }

        uint256 newBatchId = currentBatchId + 1;
        batchId = newBatchId;

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
        ISettlement.Batch storage existBatch = batches[_batchId];
        if (existBatch.rootHash == bytes32(0)) revert InvalidBatchId();

        uint256 itemsLength = _items.length;
        
        bytes32[] memory leaves = new bytes32[](itemsLength);
        
        for (uint256 i = 0; i < itemsLength; i++) {
            ISettlement.SettlementItem calldata item = _items[i];
            
            if (orders[item.orderId].orderId != 0 || orders[item.orderId].businessOrderId != 0) {
                revert OrderAlreadyExists();
            }
            
            leaves[i] = generateLeaf(_batchId, item);
        }

        bytes32 batchRootHash = merkle.getRoot(leaves);
        
        bytes32 finalRootHash = generateFinalRootHash(batchRootHash, existBatch.previousRootHash);
        
        if (finalRootHash != existBatch.rootHash) {
            revert MismatchRootHash();
        }

        address assetContractCache = assetContract;
        
        for (uint256 i = 0; i < itemsLength; i++) {
            ISettlement.SettlementItem calldata item = _items[i];
            
            orders[item.orderId] = item;

            bytes32[] memory proof = merkle.getProof(leaves, i);
            if (!merkle.verifyProof(batchRootHash, proof, leaves[i])) {
                revert ErrInvalidProof();
            }

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

    function generateLeaf(uint256 _batchId, ISettlement.SettlementItem calldata item) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                _batchId, item.orderId, item.businessOrderId, item.user, item.amount, item.isAdd, item.isSettleFee
            )
        );
    }

    function generateFinalRootHash(bytes32 batchRootHash, bytes32 previousRootHash) public view returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = batchRootHash;
        leaves[1] = previousRootHash;
        return merkle.getRoot(leaves);
    }
}
