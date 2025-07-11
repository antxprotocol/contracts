// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IAsset {
    // Events
    event SignersUpdated(address[] signers);
    event SystemAddressUpdated(address indexed systemAddress);
    event LastBatchTimeUpdated(uint256 time);
    event UserWithdraw(uint256 clientOrderId,address indexed user, uint256 amount);
    event ForceWithdraw(address indexed user, uint256 amount);
    event BatchUpdated(uint256 batchId, uint256 time);
    event SettlementAddressUpdated(address indexed settlementAddress);
    event UpdateUserBalance(uint256 batchId, address indexed user, uint256 amount);
    event SystemWithdraw(address indexed to, uint256 amount);
    event WithdrawOperatorUpdated(address indexed withdrawOperator);

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
    
    // State-changing functions
    function batchWithdraw(uint256 []memory clientOrderIds,address []memory users, uint256 []memory amounts,bytes[] memory signatures) external;
    function forceWithdraw(uint256 amount) external;
    function setSigners(address[] memory _signers) external;
    function setSystemAddress(address _systemAddress) external;
    function setSettlementAddress(address _settlementAddress) external;
    function setWithdrawOperator(address _withdrawOperator) external;
    function updateUserBalances(uint256 batchId,address []memory users, uint256 []memory amounts) external;
}
