// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IEd25519Oracle} from "./interfaces/IEd25519Oracle.sol";
import "./interfaces/IAsset.sol";

contract Asset is Ownable, ReentrancyGuard, IAsset {
    using SafeERC20 for IERC20;

    IERC20 public immutable USDC;
    address[] public signers;
    address public systemAddress;
    address public settlementOperator;
    address public withdrawOperator;
    mapping(bytes32 => uint256) public userBalance;
    uint256 public lastBatchId;
    uint256 public lastBatchTime;
    IEd25519Oracle public ed25519Oracle;
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

    modifier onlySettlementOperator() {
        if (msg.sender != settlementOperator) revert OnlySettlementOperator();
        _;
    }

    modifier onlyWithdrawOperator() {
        if (msg.sender != withdrawOperator) revert OnlyWithdrawOperator();
        _;
    }

    constructor(
    address _USDC, 
    address[] memory _signers,
    address _settlementAddress,
    address _withdrawOperator,
    address _ed25519Oracle) Ownable(msg.sender) {
        if (_USDC == address(0)) revert ZeroAddressNotAllowed();
        USDC = IERC20(_USDC);

        if (_settlementAddress == address(0)) revert ZeroAddressNotAllowed();
        settlementOperator = _settlementAddress;

        if (_withdrawOperator == address(0)) revert ZeroAddressNotAllowed();
        withdrawOperator = _withdrawOperator;

        // Check signers
        if (_signers.length == 0) revert ZeroAddressNotAllowed();
        for (uint256 i = 0; i < _signers.length; i++) {
            if (_signers[i] == address(0)) revert ZeroAddressNotAllowed();
        }
        signers = _signers;
        emit SignersUpdated(_signers);

        if (_ed25519Oracle != address(0)) {
            ed25519Oracle = IEd25519Oracle(_ed25519Oracle);
            emit Ed25519OracleUpdated(_ed25519Oracle);
        }
    }

    function batchWithdraw(uint256 []memory clientOrderIds,bytes32 []memory users, uint256 []memory amounts,bytes[] memory signatures,SignatureType signatureType) external nonReentrant onlyWithdrawOperator {
        if (users.length != amounts.length) revert UserAndAmountLengthNotMatch();
        if (users.length != signatures.length) revert UserAndSignatureLengthNotMatch();

        for (uint256 i = 0; i < users.length; i++) {
            _userWithdraw(clientOrderIds[i],users[i],amounts[i],signatures[i],false,signatureType);
            emit UserWithdraw(clientOrderIds[i],users[i],amounts[i]);
        }
    }

    function forceWithdraw(bytes32 user,uint256 amount,SignatureType signatureType,bytes memory signatures) external nonReentrant validAmount(amount) {
        // check time lock
        if (block.timestamp < lastBatchTime + FORCE_WITHDRAW_TIME_LOCK) revert TimeLockNotPassed();
        // force withdraw
        _userWithdraw(0, user, amount, signatures, true, signatureType);
        emit ForceWithdraw(user, amount);
    }

    function _userWithdraw(uint256 clientOrderId,bytes32 user, uint256 amount,bytes memory signatures,bool isForce,SignatureType signatureType) internal validAmount(amount) {
        if (!isForce) {
            // check user signature
            bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", clientOrderId, user, amount, block.chainid));
            operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
            if (signatureType == SignatureType.ECDSA) {
                if (user != bytes32(uint256(uint160(ECDSA.recover(operationHash, signatures))))) revert InvalidUserSignature();
            } else {
                if (!ed25519Oracle.isVerified(user, operationHash, signatures)) revert InvalidUserSignature();
            }
        }

        // check user balance
        if (userBalance[user] < amount) revert InsufficientUserBalance(userBalance[user], amount);

        // update user balance
        userBalance[user] -= amount;
        emit UserWithdraw(clientOrderId, user, amount);

        // Store balance before transfer
        uint256 preBalance = USDC.balanceOf(address(this));
        
        // Execute transfer
        IERC20(USDC).safeTransfer(address(uint160(uint256(user))), amount);
        
        // Verify transfer happened correctly 
        uint256 postBalance = USDC.balanceOf(address(this));
        assert(preBalance - postBalance == amount);
    }

    function emergencyWithdraw(
        address token,
        address to, 
        uint256 amount,
        uint256 expireTime, 
        address[] memory allSigners,
        bytes[] memory signatures
    ) external nonReentrant validAddress(to) validAmount(amount) {
        if (token != address(USDC)) revert NotAllowedToken(token);
        if (allSigners.length < 2) revert InvalidAllSignersLength();
        if (allSigners.length != signatures.length) revert InvalidSignaturesLength();
        if (allSigners[0] == allSigners[1]) revert SameSigner();
        if (expireTime < block.timestamp) revert ExpiredTransaction();

        // verify multi signatures
        bytes32 operationHash = keccak256(abi.encodePacked("EMERGENCY_WITHDRAW", token, to, amount, expireTime, address(this), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        for (uint8 index = 0; index < allSigners.length; index++) {
            address signer = ECDSA.recover(operationHash, signatures[index]);
            if (signer != allSigners[index]) revert InvalidSigner();
            if (!isAllowedSigner(signer)) revert NotAllowedSigner();
        }
        
        // Store balance before transfer
        uint256 preBalance = IERC20(token).balanceOf(address(this));
        
        // Execute transfer
        IERC20(token).safeTransfer(to, amount);

        // Verify transfer happened correctly
        uint256 postBalance = IERC20(token).balanceOf(address(this));
        assert(preBalance - postBalance == amount);

        emit EmergencyWithdraw(to, amount);
    }

    // Interface-required signature
    function updateUserBalances(uint256 batchId,bytes32 []memory users, uint256 []memory amounts) public onlySettlementOperator {
        if (batchId != lastBatchId + 1) revert InvalidBatchId();
        if (users.length != amounts.length) revert UserAndAmountLengthNotMatch();
        for (uint256 i = 0; i < users.length; i++) {
            userBalance[users[i]] = amounts[i];
            emit UpdateUserBalance(batchId, users[i], amounts[i]);
        }

        lastBatchId = batchId;
        lastBatchTime = block.timestamp;
        emit BatchUpdated(batchId,block.timestamp);
    }

    function isAllowedSigner(address signer) public view returns (bool) {
        for (uint i = 0; i < signers.length; i++) {
            if (signers[i] == signer) {
                return true;
            }
        }
        return false;
    }

    function setSettlementAddress(address _settlementAddress) external onlyOwner validAddress(_settlementAddress) {
        settlementOperator = _settlementAddress;
        emit SettlementAddressUpdated(_settlementAddress);
    }

    function setWithdrawOperator(address _withdrawOperator) external onlyOwner validAddress(_withdrawOperator) {
        withdrawOperator = _withdrawOperator;
        emit WithdrawOperatorUpdated(_withdrawOperator);
    }

    function setEd25519Oracle(address _ed25519Oracle) external onlyOwner validAddress(_ed25519Oracle) {
        ed25519Oracle = IEd25519Oracle(_ed25519Oracle);
        emit Ed25519OracleUpdated(_ed25519Oracle);
    }

    function setSigners(address[] memory _signers) external onlyOwner  {
        if (_signers.length == 0) revert ZeroAddressNotAllowed();
        for (uint256 i = 0; i < _signers.length; i++) {
            if (_signers[i] == address(0)) revert ZeroAddressNotAllowed();
        }
        signers = _signers;
        emit SignersUpdated(_signers);
    }
}
