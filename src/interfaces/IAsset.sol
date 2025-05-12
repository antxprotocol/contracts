// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IAsset {
    // Events
    event SignersUpdated(address[] signers);
    event SettlementContractUpdated(address indexed settlementContract);
    event WithdrawFee(address indexed to, uint256 amount);
    event AddFeeBalance(uint256 amount);
    event AddRiskMarginBalance(uint256 amount);
    event SubRiskMarginBalance(uint256 amount);
    event AddUserBalance(address indexed user, uint256 amount);
    event SubUserBalance(address indexed user, uint256 amount);
    event ForceWithdrawRequest(address indexed user, uint256 amount);
    event LastBatchTimeUpdated(uint256 time);
    event AcceptForceWithdrawal(address indexed user, uint256 amount);
    event UserWithdraw(address indexed user, uint256 amount);
    
    // Errors
    error NotSettlementContract();
    error InvalidSettlementContractAddress();
    error InsufficientUserBalance(address user, uint256 available, uint256 required);
    error InsufficientFeeBalance(uint256 available, uint256 required);
    error ZeroAddressNotAllowed();
    error ZeroAmountNotAllowed();
    error FeeExceedsLimit(uint256 current, uint256 toAdd, uint256 limit);
    error TransferFailed();
    error TimeLockNotPassed();
    error InvalidTime(uint256 time);
    error OnlySettlement();

    // View/Pure functions
    function getTotalBalance() external view returns (uint256);

    // State-changing functions
    function addUserBalance(address user, uint256 amount) external;
    function subUserBalance(address user, uint256 amount) external;
    function addFeeBalance(uint256 amount) external;
    function addRiskMarginBalance(uint256 amount) external;
    function subRiskMarginBalance(uint256 amount) external;
    function setLastBatchTime(uint256 time) external;
    function userWithdraw(address user, uint256 amount) external;
    function acceptForceWithdrawal(address user, uint256 amount) external;
}
