// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./interfaces/IAsset.sol";

contract Asset is Ownable, ReentrancyGuard, IAsset {
    IERC20 public immutable USDT;
    address public settlementContract;
    address[] public signers;
    mapping(address => uint256) public userBalance;
    uint256 public feeBalance;
    uint256 public lastBatchTime;
    
    uint256 public constant FORCE_WITHDRAW_TIME_LOCK = 7 days; 

    modifier onlySettlement() {
        if (msg.sender != settlementContract) revert NotSettlementContract();
        _;
    }

    modifier validAddress(address addr) {
        if (addr == address(0)) revert ZeroAddressNotAllowed();
        _;
    }

    modifier validAmount(uint256 amount) {
        if (amount == 0) revert ZeroAmountNotAllowed();
        _;
    }

    modifier validTime(uint256 time) {
        if (time == 0) revert InvalidTime(time);
        _;
    }

    constructor(address _USDT, address[] memory _signers) Ownable(msg.sender) {
        if (_USDT == address(0)) revert ZeroAddressNotAllowed();
        USDT = IERC20(_USDT);

        // Check signers
        if (_signers.length == 0) revert ZeroAddressNotAllowed();
        for (uint256 i = 0; i < _signers.length; i++) {
            if (_signers[i] == address(0)) revert ZeroAddressNotAllowed();
        }
        signers = _signers;
        emit SignersUpdated(_signers);
    }

    function setSettlementContract(address _settlementContract) external onlyOwner validAddress(_settlementContract) {
        settlementContract = _settlementContract;
        emit SettlementContractUpdated(_settlementContract);
    }

    function withdraw(uint256 amount) external nonReentrant validAmount(amount) {
        _userWithdraw(amount);
    }

    function forceWithdraw(uint256 amount) external nonReentrant validAmount(amount) {
        // check time lock
        if (block.timestamp < lastBatchTime + FORCE_WITHDRAW_TIME_LOCK) revert TimeLockNotPassed();

        _userWithdraw(amount);
        emit ForceWithdraw(msg.sender, amount);
    }

    function _userWithdraw(uint256 amount) internal validAmount(amount) {
        uint256 currentBalance = userBalance[msg.sender];
        if (amount > currentBalance) revert InsufficientUserBalance(msg.sender, currentBalance, amount);
        
        // Update state before external call to prevent reentrancy
        userBalance[msg.sender] = currentBalance - amount;
        
        // Store balance before transfer
        uint256 preBalance = USDT.balanceOf(address(this));
        
        // Execute transfer
        bool success = USDT.transfer(msg.sender, amount);
        if (!success) revert TransferFailed();
        
        // Verify transfer happened correctly (optional, for extra safety)
        uint256 postBalance = USDT.balanceOf(address(this));
        assert(preBalance - postBalance == amount);
        
        emit Withdraw(msg.sender, amount);
    }

    function withdrawFee(address to, uint256 amount) external onlyOwner nonReentrant validAddress(to) validAmount(amount) {
        if (amount > feeBalance) revert InsufficientFeeBalance(feeBalance, amount);
        
        // Update state before external call to prevent reentrancy
        feeBalance -= amount;
        
        // Store balance before transfer
        uint256 preBalance = USDT.balanceOf(address(this));
        
        // Execute transfer
        bool success = USDT.transfer(to, amount);
        if (!success) revert TransferFailed();

        // Verify transfer happened correctly
        uint256 postBalance = USDT.balanceOf(address(this));
        assert(preBalance - postBalance == amount);
        
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

    function getLastBatchTime() external view returns (uint256) {
        return lastBatchTime;
    }

    function setLastBatchTime(uint256 _lastBatchTime) external onlySettlement validTime(_lastBatchTime) {
        lastBatchTime = _lastBatchTime;
        emit LastBatchTimeUpdated(_lastBatchTime);
    }

    function addUserBalance(address user, uint256 amount) external onlySettlement validAddress(user) validAmount(amount) {
        userBalance[user] += amount;
        emit AddUserBalance(user, amount);
    }

    function subUserBalance(address user, uint256 amount) external onlySettlement validAddress(user) validAmount(amount) {
        uint256 currentBalance = userBalance[user];
        if (amount > currentBalance) revert InsufficientUserBalance(user, currentBalance, amount);
        
        userBalance[user] = currentBalance - amount;
        emit SubUserBalance(user, amount);
    }

    function addFeeBalance(uint256 amount) external onlySettlement validAmount(amount) {
        feeBalance += amount;
        emit AddFeeBalance(amount);
    }
}
