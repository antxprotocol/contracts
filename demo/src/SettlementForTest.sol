// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {CompleteMerkle} from "@murky/CompleteMerkle.sol";
import "./interfaces/ISettlement.sol";
import "./interfaces/IAsset.sol";

contract SettlementForTest is Ownable,ISettlement {
    address public assetContract;
    address[] public batchSubmitter;
    uint256 public batchId;
    bytes32 public rootHash;
    mapping(uint256 => ISettlement.SettlementItem) public orders;
    mapping(uint256 => Batch) public batches;
    CompleteMerkle internal merkle;

    modifier onlyBatchSubmitter() {
        bool isBatchSubmitter = false;
        for (uint256 i = 0; i < batchSubmitter.length; i++) {
            if (batchSubmitter[i] == msg.sender) {
                isBatchSubmitter = true;
                break;
            }
        }
        require(isBatchSubmitter, "Only batchSubmitter can call this function");
        _;
    }

    constructor(address _assetContract, address[] memory _batchSubmitter) Ownable(msg.sender) {
        assetContract = _assetContract;
        emit AssetContractUpdated(_assetContract);

        batchSubmitter = _batchSubmitter;
        emit BatchSubmitterUpdated(_batchSubmitter);

        merkle = new CompleteMerkle();
    }

    function getBatchSubmitter() external view returns (address[] memory) {
        return batchSubmitter;
    }

    function setBatchSubmitter(address[] memory _batchSubmitter) onlyOwner public {
        require(_batchSubmitter.length > 0, "Invalid batch submitter");
        batchSubmitter = _batchSubmitter;
        emit BatchSubmitterUpdated(_batchSubmitter);
    }

    function getAssetContract() external view returns (address) {
        return assetContract;
    }

    function setAssetContract(address _assetContract) onlyOwner public {
        require(_assetContract != address(0), "Invalid asset contract address");
        assetContract = _assetContract;
        emit AssetContractUpdated(_assetContract);
    }

    function submitBatch(uint256 _startBlock,uint256 _totalItems,bytes32 _rootHash) onlyBatchSubmitter public {
        bytes32 previousRootHash = bytes32(0);
        if (batchId > 0) {
            Batch memory previousBatch = batches[batchId - 1];
            previousRootHash = previousBatch.rootHash;
            require(
                _startBlock ==
                    previousBatch.startBlock + previousBatch.totalItems,
                "Invalid startBlock"
            );
        }
        require(_startBlock > 0, "Invalid start block");
        require(_totalItems > 0 && _totalItems < 1000, "Invalid total items");
        require(_rootHash != bytes32(0), "Invalid root hash");

        batchId++;  // start from 1

        batches[batchId] = Batch({
            startBlock: _startBlock,
            totalItems: _totalItems,
            rootHash: _rootHash,
            previousRootHash: previousRootHash
        });
        emit BatchSubmitted(batchId, _startBlock, _totalItems, _rootHash, previousRootHash);
    }

    function getBatch(uint256 _batchId) public view returns (Batch memory) {
        return batches[_batchId];
    }

    function finalizeSettlement(uint256 _batchId, ISettlement.SettlementItem[] memory _items) public {
        Batch memory existBatch = batches[_batchId];
        require(existBatch.rootHash != bytes32(0), "Invalid batchId");

        bytes32[] memory leaves = new bytes32[](_items.length);
        for (uint256 i = 0; i < _items.length; i++) {
            leaves[i] = generateLeaf(_batchId,_items[i]);
        }

        bytes32 batchRootHash = merkle.getRoot(leaves);
        require(batchRootHash == existBatch.rootHash &&
         generateFinalRootHash(batchRootHash, existBatch.previousRootHash) == existBatch.rootHash, "Invalid batchRootHash");

        for (uint256 i = 0; i < _items.length; i++) {
            tryInsertOrder(_items[i]);

            bytes32[] memory proof = merkle.getProof(leaves, i);
            if (!merkle.verifyProof(batchRootHash,proof, leaves[i])) {
                revert ErrInvalidProof();
            }

            settle(_items[i]);
        }
    }

    function generateLeaf(uint256 _batchId, ISettlement.SettlementItem memory item) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_batchId, item.orderId, item.user, item.amount,item.isAdd,item.isSettleFee));
    }

    function generateFinalRootHash(bytes32 batchRootHash, bytes32 previousRootHash) public view returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = batchRootHash;
        leaves[1] = previousRootHash;
        return merkle.getRoot(leaves);
    }

    function settle(ISettlement.SettlementItem memory item) internal {
        if (item.isAdd) {
            IAsset(assetContract).addUserBalance(item.user, item.amount);
        } else if (item.isSettleFee) {
            IAsset(assetContract).addFeeBalance(item.amount);
        } else {
            IAsset(assetContract).subUserBalance(item.user, item.amount);
        }

        emit Settlement(item.orderId, item.businessOrderId, item.user, item.amount, item.isAdd, item.isSettleFee);
    }
 
    function tryInsertOrder(ISettlement.SettlementItem memory item) internal {
       ISettlement.SettlementItem memory existItem = orders[item.orderId];
       require(existItem.orderId == 0, "Order already exists");
       orders[item.orderId] = item;
    }


    // for test
    function addUserBalanceForTest(address user, uint256 amount) onlyOwner public {
        IAsset(assetContract).addUserBalance(user, amount);
    }

    function addFeeBalanceForTest(uint256 amount) onlyOwner public {
        IAsset(assetContract).addFeeBalance(amount);
    }

    function subUserBalanceForTest(address user, uint256 amount) onlyOwner public {
        IAsset(assetContract).subUserBalance(user, amount);
    }
}