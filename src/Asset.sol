// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import "./interfaces/IAsset.sol";

contract Asset is Ownable, ReentrancyGuard, IAsset {
    IERC20 public immutable USDT;
    address public settlementContract;
    address[] public signers;
    mapping(address => mapping(uint256 => uint256)) public forcedWithdrawalRequest;  // user => amount => timestamp
    mapping(address => uint256) public userBalance;
    uint256 public feeBalance;
    uint256 public riskMarginBalance;
    uint256 public feeWithdrawn;
    uint256 public lastBatchTime;
    
    uint256 public constant FORCE_WITHDRAW_TIME_LOCK = 7 days; 

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

     modifier onlySettlement() {
        if (msg.sender != settlementContract) revert NotSettlementContract();
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

    function forceWithdraw(uint256 amount) external nonReentrant validAmount(amount) {
        require(amount > 0, "Amount must be greater than 0");
        // check time lock
        if (block.timestamp < lastBatchTime + FORCE_WITHDRAW_TIME_LOCK) revert TimeLockNotPassed();

        require(
            getForcedWithdrawalRequest(msg.sender, amount) == 0,
            "REQUEST_ALREADY_PENDING"
        );

        // Start timer on escape request.
        setForcedWithdrawalRequest(msg.sender, amount);

        // Log request.
        emit ForceWithdrawRequest(msg.sender, amount);
    }

    function setForcedWithdrawalRequest(address user, uint256 amount) internal {
        forcedWithdrawalRequest[user][amount] = block.timestamp;
    }

    function getForcedWithdrawalRequest(address user, uint256 amount) internal view returns (uint256) {
        return forcedWithdrawalRequest[user][amount];
    }

    function _userWithdraw(address user, uint256 amount) internal validAmount(amount) {
        // Store balance before transfer
        uint256 preBalance = USDT.balanceOf(address(this));
        
        // Execute transfer
        bool success = USDT.transfer(user, amount);
        if (!success) revert TransferFailed();
        
        // Verify transfer happened correctly (optional, for extra safety)
        uint256 postBalance = USDT.balanceOf(address(this));
        assert(preBalance - postBalance == amount);
    }

    function withdrawFee(
        address token,
        address to, 
        uint256 amount,
        uint256 expireTime, 
        address[] memory allSigners,
        bytes[] memory signatures
    ) external nonReentrant validAddress(to) validAmount(amount) {
        require(token == address(USDT),"invalid token");
        require(allSigners.length >=2, "invalid allSigners length");
        require(allSigners.length == signatures.length, "invalid signatures length");
        require(allSigners[0] != allSigners[1],"can not be same signer"); // must be different signer
        require(expireTime >= block.timestamp,"expired transaction");

        if (amount > feeBalance) revert InsufficientFeeBalance(feeBalance, amount);

        // verify multi signatures
        bytes32 operationHash = keccak256(abi.encodePacked("WITHDDRAW_FEE", token, to, amount, expireTime, address(this), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        for (uint8 index = 0; index < allSigners.length; index++) {
            address signer = ECDSA.recover(operationHash, signatures[index]);
            require(signer == allSigners[index], "invalid signer");
            require(isAllowedSigner(signer),"not allowed signer");
        }
        
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

        feeWithdrawn += amount;
        emit WithdrawFee(to, amount);
    }

    function getTotalBalance() external view returns (uint256) {
        return USDT.balanceOf(address(this));
    }

    function setLastBatchTime(uint256 _lastBatchTime) external onlySettlement nonReentrant validTime(_lastBatchTime) {
        lastBatchTime = _lastBatchTime;
        emit LastBatchTimeUpdated(_lastBatchTime);
    }

    function addUserBalance(address user, uint256 amount) external onlySettlement nonReentrant validAmount(amount) {
        userBalance[user] += amount;
        emit AddUserBalance(user, amount);
    }

    function subUserBalance(address user, uint256 amount) external onlySettlement nonReentrant validAmount(amount) {
        userBalance[user] -= amount;
        emit SubUserBalance(user, amount);
    }

    function addFeeBalance(uint256 amount) external onlySettlement nonReentrant validAmount(amount) {
        feeBalance += amount;
        emit AddFeeBalance(amount);
    }

     function addRiskMarginBalance(uint256 amount) external onlySettlement nonReentrant validAmount(amount) {
        riskMarginBalance += amount;
        emit AddRiskMarginBalance(amount);
    }

    function subRiskMarginBalance(uint256 amount) external onlySettlement nonReentrant validAmount(amount) {
        riskMarginBalance -= amount;
        emit SubRiskMarginBalance(amount);
    }

    function userWithdraw(address user, uint256 amount) external onlySettlement nonReentrant validAmount(amount) {
        _userWithdraw(user,amount);
        emit UserWithdraw(user,amount);
    }

    function acceptForceWithdrawal(address user, uint256 amount) external onlySettlement nonReentrant validAmount(amount) {
        require(
            getForcedWithdrawalRequest(user, amount) > 0,
            "REQUEST_ALREADY_PENDING"
        );
        _userWithdraw(user,amount);
        emit AcceptForceWithdrawal(user,amount);
    }

    function isAllowedSigner(address signer) public view returns (bool) {
        for (uint i = 0; i < signers.length; i++) {
            if (signers[i] == signer) {
                return true;
            }
        }
        return false;
    }

    function getUSDTAddress() external view returns (address) {
        return address(USDT);
    }

    function setSettlementContract(address _settlementContract) external onlyOwner validAddress(_settlementContract) {
        settlementContract = _settlementContract;
        emit SettlementContractUpdated(_settlementContract);
    }
}
