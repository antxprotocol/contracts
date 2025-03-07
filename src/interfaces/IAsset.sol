// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IAsset {
    event SignersUpdated(address[] signers);
    event SettlementContractUpdated(address indexed settlementContract);
    event Withdraw(address indexed user, uint256 amount);
    event WithdrawFee(address indexed to, uint256 amount);
    event AddUserBalance(address indexed user, uint256 amount);
    event SubUserBalance(address indexed user, uint256 amount);
    event AddFeeBalance(uint256 amount);

    function getTotalBalance() external view returns (uint256);
    function getUserBalance(address user) external view returns (uint256);
    function getFeeBalance() external view returns (uint256);
    function getSigners() external view returns (address[] memory);
    function getSettlementContract() external view returns (address);
    function getUSDT() external view returns (address);

    function addUserBalance(address user, uint256 amount) external;
    function subUserBalance(address user, uint256 amount) external;
    function addFeeBalance(uint256 amount) external;
}
