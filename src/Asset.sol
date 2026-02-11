// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ReentrancyGuardUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {UUPSUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interfaces/IAsset.sol";
import "./margin/MarginAsset.sol";
import "./stargate/StargateWithdraw.sol";

contract Asset is OwnableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable, IAsset {
    using SafeERC20 for IERC20;
    using MarginAsset for MarginAsset.Asset;

    // User asset update information struct
    struct BatchUpdateData {
        MarginAsset.Coin[] coinUpdates;
        MarginAsset.Exchange[] exchangeUpdates;
        MarginAsset.FundingIndex[] fundingIndexUpdates;
        MarginAsset.OraclePrice[] oraclePriceUpdates;
        MarginAsset.Subaccount[] subaccountUpdates;
        MarginAsset.PerpetualAsset[] perpetualAssetUpdates;
    }

    IERC20 public USDC;
    address[] public signers;
    address public settlementOperator;
    address public withdrawOperator;
    uint256 public lastBatchId;
    mapping(uint256 => mapping(int32 => bool)) public batchSeqIds;
    uint256 public lastBatchTime;
    uint256 public lastAntxChainHeight;
    uint256 public constant FORCE_WITHDRAW_TIME_LOCK = 7 days;
    mapping(uint256 => bool) public usedClientOrderIds; // clientOrderId => used
    uint64 public defaultCollateralCoinId;
    bool public hasBatchUpdate;
    uint256 public emergencyWithdrawNonce;

    // Stargate cross-chain withdraw adapter
    StargateWithdraw public stargateWithdraw;

    // MarginAsset storage info
    address public marginAsset;
    mapping(uint64 => MarginAsset.Coin) public coins;
    uint64[] public coinIds;
    mapping(uint64 => MarginAsset.Exchange) public exchanges;
    mapping(uint64 => MarginAsset.FundingIndex) public fundingIndexes;
    mapping(uint64 => MarginAsset.OraclePrice) public oraclePrices;
    mapping(uint64 => MarginAsset.Subaccount) public subaccounts;
    mapping(uint64 => mapping(uint64 => MarginAsset.PerpetualAsset)) public perpetualAssets;
    mapping(bytes32 => uint64) public addressToSubaccountId; // user => subaccountId (reverse mapping)

    modifier validAddress(address addr) {
        _validAddress(addr);
        _;
    }

    function _validAddress(address addr) internal pure {
        if (addr == address(0)) revert ZeroAddressNotAllowed();
    }

    modifier validAmount(uint256 amount) {
        _validAmount(amount);
        _;
    }

    function _validAmount(uint256 amount) internal pure {
        if (amount == 0) revert ZeroAmountNotAllowed();
    }

    modifier validTime(uint256 time) {
        _validTime(time);
        _;
    }

    function _validTime(uint256 time) internal pure {
        if (time == 0) revert InvalidTime(time);
    }

    modifier onlySettlementOperator() {
        _onlySettlementOperator();
        _;
    }

    function _onlySettlementOperator() internal view {
        if (msg.sender != settlementOperator) revert OnlySettlementOperator();
    }

    modifier onlyWithdrawOperator() {
        _onlyWithdrawOperator();
        _;
    }

    function _onlyWithdrawOperator() internal view {
        if (msg.sender != withdrawOperator) revert OnlyWithdrawOperator();
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Receive ETH
     * @dev Allows the contract to receive ETH for cross-chain fees
     * @notice ETH can be pre-funded to the contract to cover cross-chain withdrawal fees
     */
    receive() external payable {}

    function initialize(address _USDC, uint64 _defaultCollateralCoinId)
        external
        initializer
        validAddress(_USDC)
        validAmount(_defaultCollateralCoinId)
    {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        USDC = IERC20(_USDC);

        defaultCollateralCoinId = _defaultCollateralCoinId;
        emit DefaultCollateralCoinIdUpdated(_defaultCollateralCoinId);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function multiSigWalletDeposit(
        address chainAddress,  
        address  multiSigWallet,
        uint256  amount  
     ) external nonReentrant validAddress(chainAddress) validAddress(multiSigWallet) validAmount(amount) {
        uint64 subaccountId = addressToSubaccountId[bytes32(uint256(uint160(chainAddress)))];
        if (subaccountId != 0) {
            // check multiSigWallet is the same as the subaccount's multiSigWallet
            if (subaccounts[subaccountId].multiSigWallet != multiSigWallet) revert MultiSigWalletMismatch();
        }

        // transfer the amount from the caller to the contract
        USDC.safeTransferFrom(msg.sender, address(this), amount);
        // emit event
        emit MultiSigWalletDeposit(chainAddress, multiSigWallet, amount);
    }

    function deposit(
        address chainAddress,
        uint256 amount
    ) external nonReentrant validAddress(chainAddress) validAmount(amount) {
        // transfer the amount from the caller to the contract
        USDC.safeTransferFrom(msg.sender, address(this), amount);
        // emit event
        emit Deposit(chainAddress, amount);
    }

    function batchWithdraw(
        uint256[] memory clientOrderIds,
        uint64[] memory subaccountIds,
        bytes32[] memory recipients,
        uint256[] memory expireTimes,
        uint256[] memory amounts,
        uint256[] memory fees,
        bytes[] memory signatures,
        uint64[] memory dstChainIds,
        SignatureType signatureType
    ) external nonReentrant onlyWithdrawOperator {
        uint256 len = clientOrderIds.length;
        if (
           len != subaccountIds.length ||
           len != recipients.length ||
           len != expireTimes.length ||
           len != amounts.length ||
           len != fees.length ||
           len != signatures.length ||
           len != dstChainIds.length
       ) revert LengthNotMatch();

        for (uint64 i = 0; i < subaccountIds.length; i++) {
            bytes32 user = subaccounts[subaccountIds[i]].chainAddress;
            _userWithdraw(clientOrderIds[i], user, recipients[i], expireTimes[i], dstChainIds[i], amounts[i], fees[i], signatures[i], false, signatureType);
        }
    }

    function forceWithdraw(
        uint256 amount,
        uint64 dstChainId
    ) external nonReentrant validAmount(amount) {
        if (!hasBatchUpdate) revert NotInitLastBatchTime(); 
        // check time lock
        if (block.timestamp < lastBatchTime + FORCE_WITHDRAW_TIME_LOCK) revert TimeLockNotPassed();

        bytes32 user = bytes32(uint256(uint160(msg.sender)));
        uint64 subaccountId = addressToSubaccountId[user];
        if (subaccountId == 0) revert UserNotFound();

        // check if the subaccount is a multi-signature wallet
        MarginAsset.Subaccount memory subaccount = subaccounts[subaccountId];
        bytes32 recipient = subaccount.chainAddress;
        if (subaccount.isMultiSigWallet) {
           recipient = bytes32(uint256(uint160(subaccount.multiSigWallet)));
        }
    
        // force withdraw
        _userWithdraw(0, user, recipient, 0, dstChainId, amount, 0, "", true, SignatureType.ECDSA);
        emit ForceWithdraw(user, recipient, amount, dstChainId);
    }

    function _userWithdraw(
        uint256 clientOrderId,
        bytes32 user,
        bytes32 recipient,
        uint256 expireTime,
        uint64 dstChainId,
        uint256 amount,
        uint256 fee,
        bytes memory signatures,
        bool isForce,
        SignatureType signatureType
    ) internal validAmount(amount) {
        if (!isForce) {
            // check if the clientOrderId is already used
            if (usedClientOrderIds[clientOrderId]) revert ClientOrderIdAlreadyUsed();
            usedClientOrderIds[clientOrderId] = true;

            // check if the expireTime is expired
            if (expireTime < block.timestamp) revert ExpiredTransaction();

            // check user signature
            bytes32 operationHash =
                _hashUserWithdraw(clientOrderId, user, recipient, amount, fee, expireTime, dstChainId);
            operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
            if (signatureType == SignatureType.ECDSA) {
                if (user != bytes32(uint256(uint160(ECDSA.recover(operationHash, signatures))))) {
                    revert InvalidUserSignature();
                }
            } else {
                revert NotSupportedSignatureType();
            }
        }

        // check user available amount
        uint256 userAvailableAmount = availableAmount(user);
        if (userAvailableAmount < amount) revert InsufficientUserBalance(userAvailableAmount, amount);


        uint64 subaccountId = addressToSubaccountId[user];
        if (subaccountId == 0) revert UserNotFound();

        MarginAsset.Subaccount memory subaccount = subaccounts[subaccountId];
        if (subaccount.isMultiSigWallet) {
            // multi-signature wallet can only withdraw to the same chain
            if (dstChainId != block.chainid) {
                revert NotAllowedCrossChainWithdraw();
            }
            // check if the recipient is the multi-signature wallet
            if (recipient != bytes32(uint256(uint160(subaccount.multiSigWallet)))) {
                revert MultiSigWalletMismatch();
            }
        }

        // get USDC decimals
        uint8 usdcDecimals = IERC20Metadata(address(USDC)).decimals();
        // convert coin stepSizeScale decimals to usdcDecimals
        uint256 transferAmount;

        MarginAsset.Coin memory coin = coins[defaultCollateralCoinId];
        if (usdcDecimals > coin.stepSizeScale) {
            uint256 scaleDiff = usdcDecimals - coin.stepSizeScale;
            transferAmount = amount * 10 ** scaleDiff;
        } else if (usdcDecimals < coin.stepSizeScale) {
            uint256 scaleDiff = coin.stepSizeScale - usdcDecimals;
            transferAmount = amount / 10 ** scaleDiff;
        } else {
            transferAmount = amount;
        }

        // check if the dstChainId is native chain
        if (dstChainId == block.chainid) {
            // Store balance before transfer
            uint256 preBalance = USDC.balanceOf(address(this));

            // Execute transfer
            IERC20(USDC).safeTransfer(address(uint160(uint256(recipient))), transferAmount);

            // Verify transfer happened correctly
            uint256 postBalance = USDC.balanceOf(address(this));
            assert(preBalance - postBalance == transferAmount);
            // emit event
            emit UserWithdraw(clientOrderId, user, recipient, transferAmount, dstChainId);
        } else {
            // cross-chain withdraw
            // Approve StargateWithdraw to spend USDC
            USDC.forceApprove(address(stargateWithdraw), transferAmount);

            // Prepare send parameters
            (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
                stargateWithdraw.prepareTakeTaxi(dstChainId, transferAmount, recipient);

            // Check if contract has sufficient ETH balance for cross-chain fees
            if (address(this).balance < valueToSend) {
                revert InsufficientEthBalance(valueToSend, address(this).balance);
            }

            // Execute cross-chain withdraw
            stargateWithdraw.crossChainWithdraw{
                value: valueToSend
            }(clientOrderId, user, transferAmount, dstChainId, recipient, address(this), sendParam, messagingFee);

            // Reset approval
            USDC.forceApprove(address(stargateWithdraw), 0);

            emit CrossChainWithdraw(clientOrderId, user, recipient, transferAmount, dstChainId);
        }
    }

    /**
     * @dev Calculate available amount for a user with optional collateralCoinId
     * @param user User address (bytes32 format)
     * @param collateralCoinId Collateral coin ID (0 means auto-find first available)
     * @return Available amount
     */
    function _calculateAvailableAmount(bytes32 user, uint64 collateralCoinId) internal view returns (int256) {
        // Directly find subaccountId through reverse mapping
        uint64 subaccountId = addressToSubaccountId[user];
        if (subaccountId == 0) return 0;

        MarginAsset.Subaccount memory subaccount = subaccounts[subaccountId];
        if (subaccount.id == 0) return 0;

        // Find corresponding PerpetualAsset
        MarginAsset.PerpetualAsset memory perpetualAsset;
        uint64 targetCollateralCoinId = collateralCoinId;
        bool foundPerpetualAsset = false;

        if (collateralCoinId == 0) {
            // Auto-find: iterate through all possible collateralCoinIds
            for (uint256 i = 0; i < coinIds.length; i++) {
                uint64 coinId = coinIds[i];
                MarginAsset.PerpetualAsset memory pa = perpetualAssets[subaccountId][coinId];
                if (pa.subaccountId == subaccountId && pa.collateralCoinId > 0) {
                    perpetualAsset = pa;
                    targetCollateralCoinId = pa.collateralCoinId;
                    foundPerpetualAsset = true;
                    break;
                }
            }
        } else {
            // Use specified collateralCoinId
            perpetualAsset = perpetualAssets[subaccountId][collateralCoinId];
            if (perpetualAsset.subaccountId == subaccountId && perpetualAsset.collateralCoinId > 0) {
                targetCollateralCoinId = perpetualAsset.collateralCoinId;
                foundPerpetualAsset = true;
            }
        }

        if (!foundPerpetualAsset) return 0;
        if (perpetualAsset.positions.length == 0) return int256(int64(perpetualAsset.crossCollateralAmount));

        // Get collateral coin information
        MarginAsset.Coin memory collateralCoin = coins[targetCollateralCoinId];
        if (collateralCoin.id == 0) revert CoinNotFound();

        // Build arrays in a single loop to optimize gas consumption
        uint256 tradeSettingsLength = subaccount.tradeSettings.length;
        MarginAsset.Exchange[] memory exchangeArray = new MarginAsset.Exchange[](tradeSettingsLength);
        MarginAsset.OraclePrice[] memory oraclePriceArray = new MarginAsset.OraclePrice[](tradeSettingsLength);
        MarginAsset.FundingIndex[] memory fundingIndexArray = new MarginAsset.FundingIndex[](tradeSettingsLength);

        // Single loop to populate all three arrays (optimized from 3 separate loops)
        for (uint256 i = 0; i < tradeSettingsLength; i++) {
            uint64 exchangeId = subaccount.tradeSettings[i].exchangeId;
            exchangeArray[i] = exchanges[exchangeId];
            oraclePriceArray[i] = oraclePrices[exchangeId];
            fundingIndexArray[i] = fundingIndexes[exchangeId];
        }

        // Build Subaccount (use subaccount from storage, but update chainAddress)
        MarginAsset.Subaccount memory subaccountForCalc = MarginAsset.Subaccount({
            id: subaccountId,
            chainAddress: user,
            isMultiSigWallet: subaccount.isMultiSigWallet,
            multiSigWallet: subaccount.multiSigWallet,
            clientAccountId: subaccount.clientAccountId,
            tradeSettings: subaccount.tradeSettings
        });

        MarginAssetCalculator calculator = MarginAssetCalculator(marginAsset);
        return calculator.getCrossTransferOutAvailableAmount(
            collateralCoin, exchangeArray, oraclePriceArray, fundingIndexArray, subaccountForCalc, perpetualAsset
        );
    }

    /**
     * @notice Get available amount for a user (auto-find collateralCoinId)
     * @param user User address (bytes32 format)
     * @return Available amount
     */
    function availableAmount(bytes32 user) public view returns (uint256) {
        return availableAmount(user, defaultCollateralCoinId);
    }

    /**
     * @notice Get available amount for a user with specified collateralCoinId
     * @param user User address (bytes32 format)
     * @param collateralCoinId Collateral coin ID (0 means auto-find first available)
     * @return Available amount
     */
    function availableAmount(bytes32 user, uint64 collateralCoinId) public view returns (uint256) {
        int256 userAvailableAmount = _calculateAvailableAmount(user, collateralCoinId);
        if (userAvailableAmount < 0) return 0;
        return uint256(userAvailableAmount);
    }

    /**
     * @notice Get available amount by subaccount ID (auto-find collateralCoinId)
     * @param subAccountId Subaccount ID
     * @return Available amount
     */
    function availableAmountBySubAccountId(uint64 subAccountId) public view returns (uint256) {
        return availableAmountBySubAccountId(subAccountId, defaultCollateralCoinId);
    }

    /**
     * @notice Get available amount by subaccount ID with specified collateralCoinId
     * @param subAccountId Subaccount ID
     * @param collateralCoinId Collateral coin ID (0 means auto-find first available)
     * @return Available amount
     */
    function availableAmountBySubAccountId(uint64 subAccountId, uint64 collateralCoinId) public view returns (uint256) {
        MarginAsset.Subaccount memory subaccount = subaccounts[subAccountId];
        if (subaccount.id == 0) revert UserNotFound();
        int256 subaccountAvailableAmount = _calculateAvailableAmount(subaccount.chainAddress, collateralCoinId);
        if (subaccountAvailableAmount < 0) return 0;
        return uint256(subaccountAvailableAmount);
    }

    function emergencyWithdraw(
        address token,
        address to,
        uint256 amount,
        uint256 expireTime,
        uint256 nonce,
        address[] memory allSigners,
        bytes[] memory signatures
    ) external nonReentrant validAddress(to) validAmount(amount) {
        // Function disabled - emergency withdraw is no longer supported
        revert FunctionDisabled();
    }

    function emergencyWithdrawETH(
        address to,
        uint256 amount,
        uint256 expireTime,
        uint256 nonce,
        address[] memory allSigners,
        bytes[] memory signatures
    ) external nonReentrant validAddress(to) validAmount(amount) {
        // Function disabled - emergency withdraw ETH is no longer supported
        revert FunctionDisabled();
    }

    /**
     * @notice Batch update user asset info
     * @param batchId Batch ID, must equal lastBatchId + 1
     * @param antxChainHeight AntX chain height
     * @param batchUpdateData Batch update data
     */
    function batchUpdate(
        uint256 batchId,
        int32 seqInBatch,
        uint256 antxChainHeight,
        BatchUpdateData memory batchUpdateData
    ) public onlySettlementOperator {
        // Validate batchId: must be lastBatchId + 1, or lastBatchId with unused seqInBatch
        if (batchId == lastBatchId) {
            // If using same batchId, seqInBatch must not be used
            if (batchSeqIds[batchId][seqInBatch]) revert InvalidBatchId();
        } else if (batchId != lastBatchId + 1) {
            // If not same batchId, must be sequential
            revert InvalidBatchId();
        }
        if (antxChainHeight <= lastAntxChainHeight) revert InvalidAntxChainHeight();
        if (marginAsset == address(0)) revert ZeroAddressNotAllowed();

        if (batchUpdateData.coinUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.coinUpdates.length; i++) {
                coins[batchUpdateData.coinUpdates[i].id] = batchUpdateData.coinUpdates[i];
                emit CoinInfoUpdated(
                    batchUpdateData.coinUpdates[i].id,
                    batchUpdateData.coinUpdates[i].symbol,
                    batchUpdateData.coinUpdates[i].stepSizeScale
                );

                // Ensure coin id exists in coinIds array
                bool existCoin = false;
                for (uint256 j = 0; j < coinIds.length; j++) {
                    if (coinIds[j] == batchUpdateData.coinUpdates[i].id) {
                        existCoin = true;
                        break;
                    }
                }
                if (!existCoin) coinIds.push(batchUpdateData.coinUpdates[i].id);
            }
        }
        if (batchUpdateData.exchangeUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.exchangeUpdates.length; i++) {
                exchanges[batchUpdateData.exchangeUpdates[i].exchangeId] = batchUpdateData.exchangeUpdates[i];
                emit ExchangeInfoUpdated(
                    batchUpdateData.exchangeUpdates[i].exchangeId,
                    batchUpdateData.exchangeUpdates[i].stepSizeScale,
                    batchUpdateData.exchangeUpdates[i].tickSizeScale,
                    0,
                    0,
                    batchUpdateData.exchangeUpdates[i].riskTiers
                );
            }
        }
        if (batchUpdateData.fundingIndexUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.fundingIndexUpdates.length; i++) {
                fundingIndexes[batchUpdateData.fundingIndexUpdates[i].exchangeId] =
                    batchUpdateData.fundingIndexUpdates[i];
                emit FundingIndexUpdated(
                    batchUpdateData.fundingIndexUpdates[i].exchangeId,
                    batchUpdateData.fundingIndexUpdates[i].fundingIndex
                );
            }
        }
        if (batchUpdateData.oraclePriceUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.oraclePriceUpdates.length; i++) {
                oraclePrices[batchUpdateData.oraclePriceUpdates[i].exchangeId] = batchUpdateData.oraclePriceUpdates[i];
                emit OraclePriceUpdated(
                    batchUpdateData.oraclePriceUpdates[i].exchangeId,
                    batchUpdateData.oraclePriceUpdates[i].oraclePrice,
                    batchUpdateData.oraclePriceUpdates[i].oracleTime
                );
            }
        }

        if (batchUpdateData.subaccountUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.subaccountUpdates.length; i++) {
                addressToSubaccountId[batchUpdateData.subaccountUpdates[i].chainAddress] =
                    batchUpdateData.subaccountUpdates[i].id;
                subaccounts[batchUpdateData.subaccountUpdates[i].id] = batchUpdateData.subaccountUpdates[i];
                emit SubaccountUpdated(
                    batchUpdateData.subaccountUpdates[i].id,
                    batchUpdateData.subaccountUpdates[i].chainAddress,
                    batchUpdateData.subaccountUpdates[i].clientAccountId,
                    batchUpdateData.subaccountUpdates[i].tradeSettings
                );
            }
        }
        if (batchUpdateData.perpetualAssetUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.perpetualAssetUpdates.length; i++) {
                uint64 collateralCoinId = batchUpdateData.perpetualAssetUpdates[i].collateralCoinId;
                perpetualAssets[batchUpdateData.perpetualAssetUpdates[i].subaccountId][collateralCoinId] =
                    batchUpdateData.perpetualAssetUpdates[i];
                emit PerpetualAssetUpdated(
                    batchUpdateData.perpetualAssetUpdates[i].subaccountId,
                    collateralCoinId,
                    batchUpdateData.perpetualAssetUpdates[i].crossCollateralAmount,
                    batchUpdateData.perpetualAssetUpdates[i].positions
                );
            }
        }

        if (!hasBatchUpdate) {
            hasBatchUpdate = true;
        }
        lastBatchId = batchId;
        batchSeqIds[batchId][seqInBatch] = true;
        lastBatchTime = block.timestamp;
        lastAntxChainHeight = antxChainHeight;
        emit BatchUpdated(batchId, antxChainHeight, block.timestamp);
    }

    function isAllowedSigner(address signer) public view returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
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

    function setSigners(address[] memory _signers) external onlyOwner {
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

    function setStargateWithdraw(address _stargateWithdraw) external onlyOwner validAddress(_stargateWithdraw) {
        if (_stargateWithdraw == address(0)) revert ZeroAddressNotAllowed();
        stargateWithdraw = StargateWithdraw(payable(_stargateWithdraw));
        emit StargateWithdrawUpdated(_stargateWithdraw);
    }

    function setDefaultCollateralCoinId(uint64 _defaultCollateralCoinId) external onlyOwner {
        if (_defaultCollateralCoinId == 0) revert InvalidCollateralCoinId();
        defaultCollateralCoinId = _defaultCollateralCoinId;
        emit DefaultCollateralCoinIdUpdated(_defaultCollateralCoinId);
    }

    /**
     * @dev Optimized hash function for USER_WITHDRAW operation using inline assembly
     * Equivalent to: keccak256(abi.encodePacked("USER_WITHDRAW", clientOrderId, user, recipient, amount, expireTime, dstChainId, block.chainid, address(this)))
     */
    function _hashUserWithdraw(
        uint256 clientOrderId,
        bytes32 user,
        bytes32 recipient,
        uint256 amount,
        uint256 fee,
        uint256 expireTime,
        uint64 dstChainId
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "USER_WITHDRAW",
                clientOrderId,
                user,
                recipient,
                amount,
                fee,
                expireTime,
                dstChainId,
                block.chainid,
                address(this)
            )
        );
    }


    uint256[50] private __gap; // allow for future upgrades
}
