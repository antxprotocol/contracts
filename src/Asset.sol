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
    struct BatchUpdateData {
        MarginAsset.Subaccount []subaccountUpdates;
        MarginAsset.PerpetualAsset []perpetualAssetUpdates;
    }

    IERC20 public immutable USDC;
    address[] public signers;
    address public systemAddress;
    address public settlementOperator;
    address public withdrawOperator;
    uint256 public lastBatchId;
    uint256 public lastBatchTime;
    uint256 public lastAntxChainHeight;
    IEd25519Oracle public ed25519Oracle;
    uint256 public constant FORCE_WITHDRAW_TIME_LOCK = 7 days; 

    // MarginAsset storage info
    address public marginAsset;
    mapping(uint64 => MarginAsset.Coin) public coins;
    uint64[] public coinIds;
    mapping(uint64 => MarginAsset.Exchange) public exchanges;
    mapping(uint64 => MarginAsset.FundingIndex) public fundingIndexes;
    mapping(uint64 => MarginAsset.OraclePrice) public oraclePrices;
    mapping(uint64 => MarginAsset.Subaccount) public subaccounts;
    mapping(uint64 => mapping(uint64 => MarginAsset.PerpetualAsset)) public perpetualAssets;
    mapping(bytes32 => uint64) public addressToSubAccountId; // user => subaccountId (reverse mapping)

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

    function batchWithdraw(uint256 []memory clientOrderIds,uint64 []memory subaccountIds, uint256 []memory amounts,bytes[] memory signatures,SignatureType signatureType) external nonReentrant onlyWithdrawOperator {
        if (subaccountIds.length != amounts.length) revert UserAndAmountLengthNotMatch();
        if (subaccountIds.length != signatures.length) revert UserAndSignatureLengthNotMatch();

        for (uint64 i = 0; i < subaccountIds.length; i++) {
            bytes32 user = subaccounts[subaccountIds[i]].chainAddress;
            _userWithdraw(clientOrderIds[i],user,amounts[i],signatures[i],false,signatureType);
            emit UserWithdraw(clientOrderIds[i],user,amounts[i]);
        }
    }

    function forceWithdraw(uint64 subaccountId,uint256 amount,SignatureType signatureType,bytes memory signatures) external nonReentrant validAmount(amount) {
        // check time lock
        if (block.timestamp < lastBatchTime + FORCE_WITHDRAW_TIME_LOCK) revert TimeLockNotPassed();
        // force withdraw
        bytes32 user = subaccounts[subaccountId].chainAddress;
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
        // 直接通过反向映射查找subaccountId
        uint64 subaccountId = addressToSubAccountId[user];
        if (subaccountId == 0) return 0;
        
        MarginAsset.Subaccount memory subaccount = subaccounts[subaccountId];
        if (subaccount.id == 0) return 0;

        // 查找对应的PerpetualAsset（遍历所有可能的collateralCoinId）
        MarginAsset.PerpetualAsset memory perpetualAsset;
        uint64 collateralCoinId = 0;
        bool foundPerpetualAsset = false;
        for (uint256 i = 0; i < coinIds.length; i++) {
            uint64 coinId = coinIds[i];
            MarginAsset.PerpetualAsset memory pa = perpetualAssets[subaccountId][coinId];
            if (pa.subaccountId == subaccountId && pa.collateralCoinId > 0) {
                perpetualAsset = pa;
                collateralCoinId = pa.collateralCoinId;
                foundPerpetualAsset = true;
                break;
            }
        }
        
        if (!foundPerpetualAsset) return 0;
        if (perpetualAsset.crossCollateralAmount <= 0) return 0;
        if (perpetualAsset.positions.length == 0) return uint256(uint64(perpetualAsset.crossCollateralAmount));

        // 获取抵押品币种信息
        MarginAsset.Coin memory collateralCoin = coins[collateralCoinId];
        if (collateralCoin.id == 0) {
            // Coin未设置，无法计算可用金额
            revert("Coin not found");
        }

        // 构建Exchange数组
        MarginAsset.Exchange[] memory exchangeArray = new MarginAsset.Exchange[](subaccount.tradeSettings.length);
        for (uint256 i = 0; i < subaccount.tradeSettings.length; i++) {
            uint64 exchangeId = subaccount.tradeSettings[i].exchangeId;
            exchangeArray[i] = exchanges[exchangeId];
        }

        // 构建OraclePrice数组
        MarginAsset.OraclePrice[] memory oraclePriceArray = new MarginAsset.OraclePrice[](subaccount.tradeSettings.length);
        for (uint256 i = 0; i < subaccount.tradeSettings.length; i++) {
            uint64 exchangeId = subaccount.tradeSettings[i].exchangeId;
            oraclePriceArray[i] = oraclePrices[exchangeId];
        }

        // 构建FundingIndex数组
        MarginAsset.FundingIndex[] memory fundingIndexArray = new MarginAsset.FundingIndex[](subaccount.tradeSettings.length);
        for (uint256 i = 0; i < subaccount.tradeSettings.length; i++) {
            uint64 exchangeId = subaccount.tradeSettings[i].exchangeId;
            fundingIndexArray[i] = fundingIndexes[exchangeId];
        }

        // 构建Subaccount（使用存储中的subaccount，但更新chainAddress）
        MarginAsset.Subaccount memory subaccountForCalc = MarginAsset.Subaccount({
            id: subaccountId,
            chainAddress: user,
            clientAccountId: subaccount.clientAccountId,
            isSystemAccount: subaccount.isSystemAccount,
            tradeSettings: subaccount.tradeSettings
        });

        // orderFrozenAmount暂时设为0，需要从其他地方获取
        uint256 orderFrozenAmount = 0;

        MarginAssetCalculator calculator = MarginAssetCalculator(marginAsset);
        return calculator.getCrossTransferOutAvailableAmount(
            collateralCoin,
            exchangeArray,
            oraclePriceArray,
            fundingIndexArray,
            subaccountForCalc,
            perpetualAsset,
            orderFrozenAmount
        );
    }

    function availableAmount(bytes32 user) public view returns (uint256) {
        return _calculateAvailableAmount(user);
    }

    function availableAmountBySubAccountId(uint64 subAccountId) public view returns (uint256) {
        MarginAsset.Subaccount memory subaccount = subaccounts[subAccountId];
        if (subaccount.id == 0) revert UserNotFound();
        return _calculateAvailableAmount(subaccount.chainAddress);
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
     * @param batchUpdateData Batch update data
     */
    function batchUpdate(
        uint256 batchId,
        uint256 antxChainHeight,
        BatchUpdateData memory batchUpdateData
    ) public onlySettlementOperator {
        if (batchId != lastBatchId + 1) revert InvalidBatchId();
        if (antxChainHeight <= lastAntxChainHeight) revert InvalidAntxChainHeight();
        if (marginAsset == address(0)) revert ZeroAddressNotAllowed();
        
        if (batchUpdateData.subaccountUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.subaccountUpdates.length; i++) {
                addressToSubAccountId[batchUpdateData.subaccountUpdates[i].chainAddress] = batchUpdateData.subaccountUpdates[i].id;
                subaccounts[batchUpdateData.subaccountUpdates[i].id] = batchUpdateData.subaccountUpdates[i];
            }
        }
        if (batchUpdateData.perpetualAssetUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.perpetualAssetUpdates.length; i++) {
                uint64 collateralCoinId = batchUpdateData.perpetualAssetUpdates[i].collateralCoinId;
                perpetualAssets[batchUpdateData.perpetualAssetUpdates[i].subaccountId][collateralCoinId] = batchUpdateData.perpetualAssetUpdates[i];
                
                // Ensure coin exists in coinIds array
                bool coinExists = false;
                for (uint256 j = 0; j < coinIds.length; j++) {
                    if (coinIds[j] == collateralCoinId) {
                        coinExists = true;
                        break;
                    }
                }
                if (!coinExists && collateralCoinId > 0) {
                    coinIds.push(collateralCoinId);
                }
            }
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
        emit MarginAssetAddressUpdated(_marginAsset);
    }


    function setExchangeInfo(uint64 exchangeId, string memory symbol, int32 stepSizeScale, int32 tickSizeScale, MarginAsset.RiskTier[] memory riskTiers) external onlySettlementOperator {
        exchanges[exchangeId] = MarginAsset.Exchange({
            exchangeId: exchangeId,
            symbol: symbol,
            stepSizeScale: stepSizeScale,
            tickSizeScale: tickSizeScale,
            riskTiers: riskTiers
        });

        emit ExchangeInfoUpdated(exchangeId, uint32(uint256(int256(stepSizeScale))), uint32(uint256(int256(tickSizeScale))), 0, 0, riskTiers);
    }

    function setOraclePrice(uint64 exchangeId, uint256 oraclePrice, uint64 oracleTime) external onlySettlementOperator {
        oraclePrices[exchangeId] = MarginAsset.OraclePrice({
            exchangeId: exchangeId,
            oraclePrice: oraclePrice,
            oracleTime: oracleTime
        });
        emit OraclePriceUpdated(exchangeId, oraclePrice, oracleTime);
    }

    function setFundingIndex(uint64 exchangeId, int256 fundingIndex) external onlySettlementOperator {
        fundingIndexes[exchangeId] = MarginAsset.FundingIndex({
            exchangeId: exchangeId,
            fundingIndex: fundingIndex
        });
        emit FundingIndexUpdated(exchangeId, fundingIndex);
    }

    function setCoin(uint64 coinId, string memory symbol, int32 stepSizeScale) external onlySettlementOperator {
        bool existCoin = false;
        for (uint256 i = 0; i < coinIds.length; i++) {
            if (coinIds[i] == coinId) {
                existCoin = true;
                break;
            }
        }
        if (!existCoin) coinIds.push(coinId);

        coins[coinId] = MarginAsset.Coin({
            id: coinId,
            symbol: symbol,
            stepSizeScale: stepSizeScale
        });
        emit CoinInfoUpdated(coinId, symbol, stepSizeScale);
    }
}
