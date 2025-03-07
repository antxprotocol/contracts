// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./interfaces/IAsset.sol";

contract Asset is Ownable, IAsset {
    IERC20 public USDT;
    address public settlementContract;
    address[] public signers; // TODO: withdrawFee use this
    mapping(address => uint256) public userBalance;
    uint256 public feeBalance;

    modifier onlySettlement() {
        require(msg.sender == settlementContract, "Not settlement contract");
        _;
    }

    constructor(address _USDT, address[] memory _signers) Ownable(msg.sender) {
        USDT = IERC20(_USDT);

        signers = _signers;
        emit SignersUpdated(_signers);
    }

    function setSettlementContract(address _settlementContract) public onlyOwner {
        require(_settlementContract != address(0), "Invalid settlement contract address");
        settlementContract = _settlementContract;
        emit SettlementContractUpdated(_settlementContract);
    }

    function withdraw(uint256 amount) public {
        require(amount <= userBalance[msg.sender], "Insufficient user balance");
        userBalance[msg.sender] -= amount;
        USDT.transfer(msg.sender, amount);
        emit Withdraw(msg.sender, amount);
    }

    function withdrawFee(address to, uint256 amount) public onlyOwner {
        require(amount <= feeBalance, "Insufficient fee balance");
        feeBalance -= amount;
        USDT.transfer(to, amount);
        emit WithdrawFee(to, amount);
    }

    function getUserBalance(address user) public view returns (uint256) {
        return userBalance[user];
    }

    function getTotalBalance() public view returns (uint256) {
        return USDT.balanceOf(address(this));
    }

    function getFeeBalance() public view returns (uint256) {
        return feeBalance;
    }

    function getSigners() public view returns (address[] memory) {
        return signers;
    }

    function getSettlementContract() public view returns (address) {
        return settlementContract;
    }

    function getUSDT() public view returns (address) {
        return address(USDT);
    }

    function addUserBalance(address user, uint256 amount) external onlySettlement {
        userBalance[user] += amount;
        emit AddUserBalance(user, amount);
    }

    function subUserBalance(address user, uint256 amount) external onlySettlement {
        userBalance[user] -= amount;
        emit SubUserBalance(user, amount);
    }

    function addFeeBalance(uint256 amount) external onlySettlement {
        feeBalance += amount;
        emit AddFeeBalance(amount);
    }
}
