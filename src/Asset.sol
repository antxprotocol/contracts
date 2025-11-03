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
import "./margin/MarginAsset.sol";

contract Asset is Ownable, ReentrancyGuard, IAsset {
    using SafeERC20 for IERC20;
    using MarginAsset for MarginAsset.Asset;

    // User asset update information struct
    struct UserAssetUpdate {
        uint64 subAccountId;                    // Sub account ID
        bytes32 user;                           // User address
        UserAssetInfo userAssetInfo;            // User asset info
    }

    struct UserAssetInfo {
        int64 crossCollateralAmount;            // Cross margin collateral amount with precision of collateralCoin.StepSizeScale
        uint256 orderFrozenAmount;              // Order frozen amount with precision of collateralCoin.StepSizeScale + 6
        MarginAsset.TradeSetting[] tradeSettings; // Trade settings list
        MarginAsset.PositionInput[] positions;  // Position list
    }

    IERC20 public immutable USDC;
    address[] public signers;
    address public systemAddress;
    address public settlementOperator;
    address public withdrawOperator;
    mapping(bytes32 => UserAssetInfo) public userInfos;
    mapping(uint64 => bytes32) public userSubAccountIdToAddress;
    uint256 public lastBatchId;
    uint256 public lastBatchTime;
    uint256 public lastAntxChainHeight;
    IEd25519Oracle public ed25519Oracle;
    uint256 public constant FORCE_WITHDRAW_TIME_LOCK = 7 days; 

    // MarginAsset calculator info
    address public marginAsset;
    uint32 public globalCoinStepSizeScale;
    mapping(uint64 => MarginAsset.ExchangeInfo) public globalExchangeInfos;

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

    constructor(address _USDC) validAddress(_USDC) Ownable(msg.sender) {
        USDC = IERC20(_USDC);
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

        // check user available amount
        uint256 userAvailableAmount = availableAmount(user);
        if (userAvailableAmount < amount) revert InsufficientUserBalance(userAvailableAmount, amount);

        // Store balance before transfer
        uint256 preBalance = USDC.balanceOf(address(this));
        
        // Execute transfer
        IERC20(USDC).safeTransfer(address(uint160(uint256(user))), amount);
        
        // Verify transfer happened correctly 
        uint256 postBalance = USDC.balanceOf(address(this));
        assert(preBalance - postBalance == amount);

        // emit event
        emit UserWithdraw(clientOrderId, user, amount);
    }

    function _calculateAvailableAmount(bytes32 user) internal view returns (uint256) {
        UserAssetInfo memory userAssetInfo = userInfos[user];
        if (userAssetInfo.crossCollateralAmount <= 0) return 0;
        if (userAssetInfo.positions.length == 0) return uint256(uint64(userAssetInfo.crossCollateralAmount));

        MarginAsset.ExchangeInfo[] memory userExchangeInfo = new MarginAsset.ExchangeInfo[](userAssetInfo.tradeSettings.length);
        for (uint256 i = 0; i < userAssetInfo.tradeSettings.length; i++) {
            userExchangeInfo[i] = globalExchangeInfos[userAssetInfo.tradeSettings[i].exchangeId];
        }

        MarginAssetCalculator calculator = MarginAssetCalculator(marginAsset);
        return calculator.getCrossTransferOutAvailableAmount(
            userAssetInfo.crossCollateralAmount,
            globalCoinStepSizeScale,
            userAssetInfo.orderFrozenAmount,
            userAssetInfo.positions,
            userAssetInfo.tradeSettings,
            userExchangeInfo
        );
    }

    function availableAmount(bytes32 user) public view returns (uint256) {
        return _calculateAvailableAmount(user);
    }

    function availableAmountBySubAccountId(uint64 subAccountId) public view returns (uint256) {
        bytes32 user = userSubAccountIdToAddress[subAccountId];
        if (user == bytes32(0)) revert UserNotFound();
        return _calculateAvailableAmount(user);
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

    /**
     * @notice Batch update user asset info
     * @param batchId Batch ID, must equal lastBatchId + 1
     * @param antxChainHeight AntX chain height
     * @param userUpdates Array of user asset update information, each element contains user's asset information
     */
    function batchUpdate(
        uint256 batchId,
        uint256 antxChainHeight,
        UserAssetUpdate[] memory userUpdates
    ) public onlySettlementOperator {
        if (batchId != lastBatchId + 1) revert InvalidBatchId();
        if (antxChainHeight <= lastAntxChainHeight) revert InvalidAntxChainHeight();
        if (marginAsset == address(0)) revert ZeroAddressNotAllowed();
        

        for (uint256 i = 0; i < userUpdates.length; i++) {
            UserAssetUpdate memory update = userUpdates[i];

            bytes32 user = userSubAccountIdToAddress[update.subAccountId];
            if (user == bytes32(0)) {
                // set user and sub account id to mapping
                userSubAccountIdToAddress[update.subAccountId] = update.user;
            } 

            // create or update user asset info
            userInfos[update.user] = update.userAssetInfo;
        }

        lastBatchId = batchId;
        lastBatchTime = block.timestamp;
        lastAntxChainHeight = antxChainHeight;
        emit BatchUpdated(batchId, antxChainHeight, block.timestamp);
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

    function setMarginAsset(address _marginAsset) external onlyOwner validAddress(_marginAsset) {
        if (_marginAsset == address(0)) revert ZeroAddressNotAllowed();
        marginAsset = _marginAsset;
        emit MarginAssetUpdated(_marginAsset);
    }

    function setGlobalCoinStepSizeScale(uint32 coinStepSizeScale) external onlyOwner {
        if (coinStepSizeScale == 0) revert ZeroAmountNotAllowed();
        globalCoinStepSizeScale = coinStepSizeScale;
        emit GlobalCoinStepSizeScaleUpdated(coinStepSizeScale);
    }

    function setExchangeInfo(uint64 exchangeId, uint32 stepSizeScale, uint32 tickSizeScale, uint256 oraclePrice, uint256 fundingIndex, MarginAsset.RiskTier[] memory riskTiers) external onlySettlementOperator {
        globalExchangeInfos[exchangeId] = MarginAsset.ExchangeInfo({
            exchangeId: exchangeId,
            stepSizeScale: stepSizeScale,
            tickSizeScale: tickSizeScale,
            oraclePrice: oraclePrice,
            fundingIndex: fundingIndex,
            riskTiers: riskTiers
        });

        emit GlobalExchangeInfoUpdated(exchangeId, stepSizeScale, tickSizeScale, oraclePrice, fundingIndex, riskTiers);
    }
}
