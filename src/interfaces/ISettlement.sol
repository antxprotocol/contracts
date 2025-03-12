// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISettlement {
    struct SettlementItem {
        uint256 orderId;
        uint256 businessOrderId;
        uint256 amount;
        address user;
        bool isAdd; // true: add, false: sub
        bool isSettleFee; // true: settle fee
    }
    
    struct Batch {
        uint256 startBlock;
        uint256 totalItems;
        bytes32 rootHash;
        bytes32 previousRootHash;
    }
    
    event BatchSubmitterUpdated(address[] batchSubmitter);
    event AssetContractUpdated(address assetContract);
    event BatchSubmitted(
        uint256 batchId, uint256 startBlock, uint256 totalElements, bytes32 rootHash, bytes32 previousRootHash
    );
    event Settlement(
        uint256 orderId, uint256 businessOrderId, address user, uint256 amount, bool isAdd, bool isSettleFee
    );

    function getBatchSubmitter() external view returns (address[] memory);
    function getAssetContract() external view returns (address);
    function submitBatch(uint256 _startBlock, uint256 _totalItems, bytes32 _rootHash) external;
    function finalizeSettlement(uint256 _batchId, SettlementItem[] calldata _items) external;
}
