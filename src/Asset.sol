// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./interfaces/IAsset.sol";

contract Asset is Ownable, IAsset {
    IERC20 public immutable USDT;
    address public settlementContract;
    address[] public signers;
    mapping(address => uint256) public userBalance;
    uint256 public feeBalance;

    error NotSettlementContract();
    error InvalidSettlementContractAddress();
    error InsufficientUserBalance(address user, uint256 available, uint256 required);
    error InsufficientFeeBalance(uint256 available, uint256 required);
    
    modifier onlySettlement() {
        if (msg.sender != settlementContract) revert NotSettlementContract();
        _;
    }

    constructor(address _USDT, address[] memory _signers) Ownable(msg.sender) {
        if (_USDT == address(0)) revert InvalidSettlementContractAddress();
        USDT = IERC20(_USDT);

        signers = _signers;
        emit SignersUpdated(_signers);
    }

    function setSettlementContract(address _settlementContract) external onlyOwner {
        if (_settlementContract == address(0)) revert InvalidSettlementContractAddress();
        settlementContract = _settlementContract;
        emit SettlementContractUpdated(_settlementContract);
    }

    function withdraw(uint256 amount) external {
        uint256 currentBalance = userBalance[msg.sender];
        if (amount > currentBalance) revert InsufficientUserBalance(msg.sender, currentBalance, amount);
        
        userBalance[msg.sender] = currentBalance - amount;
        
        bool success = USDT.transfer(msg.sender, amount);
        require(success, "Transfer failed");
        
        emit Withdraw(msg.sender, amount);
    }

    function withdrawFee(address to, uint256 amount) external onlyOwner {
        if (amount > feeBalance) revert InsufficientFeeBalance(feeBalance, amount);
        
        feeBalance -= amount;
        
        bool success = USDT.transfer(to, amount);
        require(success, "Transfer failed");
        
        emit WithdrawFee(to, amount);
    }

    function getUserBalance(address user) external view returns (uint256) {
        return userBalance[user];
    }

    function getTotalBalance() external view returns (uint256) {
        return USDT.balanceOf(address(this));
    }

    function getFeeBalance() external view returns (uint256) {
        return feeBalance;
    }

    function getSigners() external view returns (address[] memory) {
        return signers;
    }

    function getSettlementContract() external view returns (address) {
        return settlementContract;
    }

    function getUSDT() external view returns (address) {
        return address(USDT);
    }

    function addUserBalance(address user, uint256 amount) external onlySettlement {
        if (user == address(0)) revert InvalidSettlementContractAddress();
        userBalance[user] += amount;
        emit AddUserBalance(user, amount);
    }

    function subUserBalance(address user, uint256 amount) external onlySettlement {
        uint256 currentBalance = userBalance[user];
        if (amount > currentBalance) revert InsufficientUserBalance(user, currentBalance, amount);
        
        userBalance[user] = currentBalance - amount;
        emit SubUserBalance(user, amount);
    }

    function addFeeBalance(uint256 amount) external onlySettlement {
        feeBalance += amount;
        emit AddFeeBalance(amount);
    }
}
