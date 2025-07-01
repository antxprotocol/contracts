// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISettlement {
    enum SettlementType {
        Deposit,
        Withdraw,
        ForceWithdraw,
        TradeFeeIn,
        TradeFeeOut,
        TransferIn,
        TransferOut,
        Liquidation,
        RiskMarginIn,
        RiskMarginOut,
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
        uint256 endBlock;
        uint256 totalItems;
        bytes32 rootHash;
        bytes32 previousRootHash;
        uint256 batchTime;
        bool finalized;
    }
    
    event AssetContractUpdated(address assetContract);
    event BatchSubmitted(
        uint256 batchId, 
        uint256 startBlock, 
        uint256 endBlock, 
        uint256 totalElements, 
        bytes32 rootHash, 
        bytes32 previousRootHash
    );
    event Settlement(
        uint256 orderId, uint256 businessOrderId, address user, uint256 amount, SettlementType types
    );
    event LogOperatorAdded(address operator);
    event LogOperatorRemoved(address operator);

    error InvalidAssetContract();
    error InvalidStartBlock();
    error InvalidTotalItems();
    error InvalidRootHash();
    error InvalidBatchId();
    error MismatchRootHash();
    error ErrInvalidProof();
    error BatchTooLarge();
    error ZeroAddressNotAllowed();
    error EmptyArrayNotAllowed();
    error TimeLockNotPassed();
    error NotOperator();
    error BatchAlreadyFinalized();
    
    function getBatch(uint256 _batchId) external view returns (Batch memory);
    function submitBatch(uint256 _startBlock, uint256 _endBlock, uint256 _totalItems, bytes32 _rootHash) external;
    function finalizeSettlement(uint256 _batchId, SettlementItem[] calldata _items) external;
    function pause() external;
    function unpause() external;
    function generateLeaf(uint256 _batchId, SettlementItem calldata _item) external view returns (bytes32);
    function generateFinalRootHash(bytes32 _batchRootHash, bytes32 _previousRootHash) external view returns (bytes32);
}
