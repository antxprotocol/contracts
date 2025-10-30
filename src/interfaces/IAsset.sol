// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IAsset {
    // Events
    event SignersUpdated(address[] signers);
    event SystemAddressUpdated(address indexed systemAddress);
    event LastBatchTimeUpdated(uint256 time);
    event UserWithdraw(uint256 clientOrderId,bytes32 indexed user, uint256 amount);
    event ForceWithdraw(bytes32 indexed user, uint256 amount);
    event BatchUpdated(uint256 batchId, uint256 antxChainHeight, uint256 time);
    event SettlementAddressUpdated(address indexed settlementAddress);
    event UpdateUserBalance(uint256 batchId, bytes32 indexed user, uint256 amount);
    event EmergencyWithdraw(address indexed to, uint256 amount);
    event WithdrawOperatorUpdated(address indexed withdrawOperator);
    event Ed25519OracleUpdated(address indexed ed25519Oracle);
    event MarginAssetUpdated(address indexed marginAsset);

    // Errors
    error InsufficientUserBalance(uint256 available, uint256 required);
    error InsufficientSystemBalance(address systemAddress, uint256 available, uint256 required);
    error ZeroAddressNotAllowed();
    error ZeroAmountNotAllowed();
    error FeeExceedsLimit(uint256 current, uint256 toAdd, uint256 limit);
    error TransferFailed();
    error TimeLockNotPassed();
    error InvalidTime(uint256 time);
    error UserAndAmountLengthNotMatch();
    error UserAndSignatureLengthNotMatch();
    error InvalidUserSignature();
    error InvalidToken();
    error InvalidAllSignersLength();
    error InvalidSignaturesLength();
    error SameSigner();
    error ExpiredTransaction();
    error InvalidSigner();
    error NotAllowedSigner();
    error OnlySettlementOperator();
    error OnlyWithdrawOperator();
    error InvalidBatchId();
    error NotAllowedToken(address token);

    enum SignatureType {
        ECDSA,
        ED25519
    }
    
    // State-changing functions
    function batchWithdraw(uint256 []memory clientOrderIds,bytes32 []memory users, uint256 []memory amounts,bytes[] memory signatures,SignatureType signatureType) external;
    function forceWithdraw(bytes32 user,uint256 amount, SignatureType signatureType, bytes memory signatures) external;
    function setSigners(address[] memory _signers) external;
    function setSettlementAddress(address _settlementAddress) external;
    function setWithdrawOperator(address _withdrawOperator) external;
}
