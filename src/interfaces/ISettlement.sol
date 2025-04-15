// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISettlement {
    enum SettlementType {
        Deposit,
        Withdraw,
        ForceWithdraw,
        OrderFilled,
        TransferIn,
        TransferOut,
        SettleFee,
        WithdrawFee
    }

    struct SettlementItem {
        uint256 orderId;
        uint256 businessOrderId;
        uint256 amount;
        address user;
        SettlementType types;
    }
    
    struct Batch {
        uint256 startBlock;
        uint256 totalItems;
        bytes32 rootHash;
        bytes32 previousRootHash;
        uint256 batchTime;
    }
    
    event BatchSubmitterUpdated(address[] batchSubmitter);
    event AssetContractUpdated(address assetContract);
    event BatchSubmitted(
        uint256 batchId, uint256 startBlock, uint256 totalElements, bytes32 rootHash, bytes32 previousRootHash
    );
    event Settlement(
        uint256 orderId, uint256 businessOrderId, address user, uint256 amount, SettlementType types
    );

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
    error BatchTooLarge();
    error TooManyItemsToFinalize();
    error ZeroAddressNotAllowed();
    error EmptyArrayNotAllowed();
    error TimeLockNotPassed();
    
    function getBatchSubmitter() external view returns (address[] memory);
    function getBatch(uint256 _batchId) external view returns (Batch memory);
    function submitBatch(uint256 _startBlock, uint256 _totalItems, bytes32 _rootHash) external;
    function finalizeSettlement(uint256 _batchId, SettlementItem[] calldata _items) external;
    function pause() external;
    function unpause() external;
}
