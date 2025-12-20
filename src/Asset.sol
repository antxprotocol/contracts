// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuardUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {UUPSUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IEd25519Oracle} from "./interfaces/IEd25519Oracle.sol";
import "./interfaces/IAsset.sol";
import "./margin/MarginAsset.sol";
import "./stargate/StargateWithdraw.sol";
import {MessagingFee} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

contract Asset is OwnableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable, IAsset {
    using SafeERC20 for IERC20;
    using MarginAsset for MarginAsset.Asset;

    // User asset update information struct
    struct BatchUpdateData {
        MarginAsset.Coin[] coinUpdates;
        MarginAsset.Exchange[] exchangeUpdates;
        MarginAsset.FundingIndex[] fundingIndexUpdates;
        MarginAsset.OraclePrice[] oraclePriceUpdates;
        MarginAsset.Subaccount []subaccountUpdates;
        MarginAsset.PerpetualAsset []perpetualAssetUpdates;
    }

    IERC20 public USDC;
    address[] public signers;
    address public settlementOperator;
    address public withdrawOperator;
    uint256 public lastBatchId;
    mapping(uint256 => mapping(int32 => bool)) public batchSeqIds;
    uint256 public lastBatchTime;
    uint256 public lastAntxChainHeight;
    IEd25519Oracle public ed25519Oracle;
    uint256 public constant FORCE_WITHDRAW_TIME_LOCK = 7 days;
    
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

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _USDC) external initializer validAddress(_USDC) {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        USDC = IERC20(_USDC);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function batchWithdraw(uint256 []memory clientOrderIds,uint64 []memory subaccountIds,bytes32 []memory recipients,uint256 []memory expireTimes,uint256 []memory amounts,bytes[] memory signatures,uint64[] memory dstChainIds,SignatureType signatureType) external nonReentrant onlyWithdrawOperator {
        if (subaccountIds.length != amounts.length) revert UserAndAmountLengthNotMatch();
        if (subaccountIds.length != signatures.length) revert UserAndSignatureLengthNotMatch();

        for (uint64 i = 0; i < subaccountIds.length; i++) {
            bytes32 user = subaccounts[subaccountIds[i]].chainAddress;
            _userWithdraw(clientOrderIds[i],user,recipients[i],expireTimes[i],dstChainIds[i],amounts[i],signatures[i],false,signatureType);
        }
    }

    function forceWithdraw(uint64 subaccountId,uint256 amount,uint256 expireTime,SignatureType signatureType,bytes memory signatures,uint64 dstChainId) external nonReentrant validAmount(amount) {
        // check time lock
        if (block.timestamp < lastBatchTime + FORCE_WITHDRAW_TIME_LOCK) revert TimeLockNotPassed();
        // force withdraw
        bytes32 user = subaccounts[subaccountId].chainAddress;
        _userWithdraw(0, user, user, expireTime, dstChainId, amount, signatures, true, signatureType);
        emit ForceWithdraw(user, user, amount, dstChainId);
    }

    function _userWithdraw(uint256 clientOrderId,bytes32 user,bytes32 recipient,uint256 expireTime,uint64 dstChainId, uint256 amount,bytes memory signatures,bool isForce,SignatureType signatureType) internal validAmount(amount) {
        if (!isForce) {
            // check user signature
            bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", clientOrderId, user, recipient, amount, expireTime,dstChainId, block.chainid, address(this)));
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

        // check if the dstChainId is native chain
        if (dstChainId == block.chainid) {
           // Store balance before transfer
            uint256 preBalance = USDC.balanceOf(address(this));
            
            // Execute transfer
            IERC20(USDC).safeTransfer(address(uint160(uint256(recipient))), amount);
            
            // Verify transfer happened correctly 
            uint256 postBalance = USDC.balanceOf(address(this));
            assert(preBalance - postBalance == amount);
             // emit event
            emit UserWithdraw(clientOrderId, user,recipient, amount,dstChainId);
        } else {
            // cross-chain withdraw
            // Approve StargateWithdraw to spend USDC
            USDC.forceApprove(address(stargateWithdraw), amount);
            
            // Execute cross-chain withdraw
            stargateWithdraw.crossChainWithdraw(clientOrderId, recipient, amount, dstChainId, user, 0, MessagingFee({nativeFee: 0, lzTokenFee: 0}), address(this));
            
            // Reset approval
            USDC.forceApprove(address(stargateWithdraw), 0);
            
            emit CrossChainWithdraw(clientOrderId, user, recipient, amount, dstChainId);
        }
    }

    function _calculateAvailableAmount(bytes32 user) internal view returns (int256) {
        // Directly find subaccountId through reverse mapping
        uint64 subaccountId = addressToSubaccountId[user];
        if (subaccountId == 0) return 0;
        
        MarginAsset.Subaccount memory subaccount = subaccounts[subaccountId];
        if (subaccount.id == 0) return 0;

        // Find corresponding PerpetualAsset (iterate through all possible collateralCoinIds)
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
        if (perpetualAsset.positions.length == 0) return int256(int64(perpetualAsset.crossCollateralAmount));

        // Get collateral coin information
        MarginAsset.Coin memory collateralCoin = coins[collateralCoinId];
        if (collateralCoin.id == 0) {
            // Coin not set, cannot calculate available amount
            revert("Coin not found");
        }

        // Build Exchange array
        MarginAsset.Exchange[] memory exchangeArray = new MarginAsset.Exchange[](subaccount.tradeSettings.length);
        for (uint256 i = 0; i < subaccount.tradeSettings.length; i++) {
            uint64 exchangeId = subaccount.tradeSettings[i].exchangeId;
            exchangeArray[i] = exchanges[exchangeId];
        }

        // Build OraclePrice array
        MarginAsset.OraclePrice[] memory oraclePriceArray = new MarginAsset.OraclePrice[](subaccount.tradeSettings.length);
        for (uint256 i = 0; i < subaccount.tradeSettings.length; i++) {
            uint64 exchangeId = subaccount.tradeSettings[i].exchangeId;
            oraclePriceArray[i] = oraclePrices[exchangeId];
        }

        // Build FundingIndex array
        MarginAsset.FundingIndex[] memory fundingIndexArray = new MarginAsset.FundingIndex[](subaccount.tradeSettings.length);
        for (uint256 i = 0; i < subaccount.tradeSettings.length; i++) {
            uint64 exchangeId = subaccount.tradeSettings[i].exchangeId;
            fundingIndexArray[i] = fundingIndexes[exchangeId];
        }

        // Build Subaccount (use subaccount from storage, but update chainAddress)
        MarginAsset.Subaccount memory subaccountForCalc = MarginAsset.Subaccount({
            id: subaccountId,
            chainAddress: user,
            clientAccountId: subaccount.clientAccountId,
            tradeSettings: subaccount.tradeSettings
        });


        MarginAssetCalculator calculator = MarginAssetCalculator(marginAsset);
        return calculator.getCrossTransferOutAvailableAmount(
            collateralCoin,
            exchangeArray,
            oraclePriceArray,
            fundingIndexArray,
            subaccountForCalc,
            perpetualAsset
        );
    }

    function availableAmount(bytes32 user) public view returns (uint256) {
        int256 userAvailableAmount = _calculateAvailableAmount(user);
        if (userAvailableAmount < 0) return 0;
        return uint256(userAvailableAmount);
    }

    function availableAmountBySubAccountId(uint64 subAccountId) public view returns (uint256) {
        MarginAsset.Subaccount memory subaccount = subaccounts[subAccountId];
        if (subaccount.id == 0) revert UserNotFound();
        int256 subaccountAvailableAmount = _calculateAvailableAmount(subaccount.chainAddress);
        if (subaccountAvailableAmount < 0) return 0;
        return uint256(subaccountAvailableAmount);
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
                emit CoinInfoUpdated(batchUpdateData.coinUpdates[i].id, batchUpdateData.coinUpdates[i].symbol, batchUpdateData.coinUpdates[i].stepSizeScale);

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
                emit ExchangeInfoUpdated(batchUpdateData.exchangeUpdates[i].exchangeId, batchUpdateData.exchangeUpdates[i].stepSizeScale, batchUpdateData.exchangeUpdates[i].tickSizeScale, 0, 0, batchUpdateData.exchangeUpdates[i].riskTiers);
            }
        }
        if (batchUpdateData.fundingIndexUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.fundingIndexUpdates.length; i++) {
                fundingIndexes[batchUpdateData.fundingIndexUpdates[i].exchangeId] = batchUpdateData.fundingIndexUpdates[i];
                emit FundingIndexUpdated(batchUpdateData.fundingIndexUpdates[i].exchangeId, batchUpdateData.fundingIndexUpdates[i].fundingIndex);
            }
        }
        if (batchUpdateData.oraclePriceUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.oraclePriceUpdates.length; i++) {
                oraclePrices[batchUpdateData.oraclePriceUpdates[i].exchangeId] = batchUpdateData.oraclePriceUpdates[i];
                emit OraclePriceUpdated(batchUpdateData.oraclePriceUpdates[i].exchangeId, batchUpdateData.oraclePriceUpdates[i].oraclePrice, batchUpdateData.oraclePriceUpdates[i].oracleTime);
            }
        }
        
        if (batchUpdateData.subaccountUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.subaccountUpdates.length; i++) {
                addressToSubaccountId[batchUpdateData.subaccountUpdates[i].chainAddress] = batchUpdateData.subaccountUpdates[i].id;
                subaccounts[batchUpdateData.subaccountUpdates[i].id] = batchUpdateData.subaccountUpdates[i];
                emit SubaccountUpdated(batchUpdateData.subaccountUpdates[i].id, batchUpdateData.subaccountUpdates[i].chainAddress, batchUpdateData.subaccountUpdates[i].clientAccountId, batchUpdateData.subaccountUpdates[i].tradeSettings);
            }
        }
        if (batchUpdateData.perpetualAssetUpdates.length > 0) {
            for (uint256 i = 0; i < batchUpdateData.perpetualAssetUpdates.length; i++) {
                uint64 collateralCoinId = batchUpdateData.perpetualAssetUpdates[i].collateralCoinId;
                perpetualAssets[batchUpdateData.perpetualAssetUpdates[i].subaccountId][collateralCoinId] = batchUpdateData.perpetualAssetUpdates[i];
                emit PerpetualAssetUpdated(batchUpdateData.perpetualAssetUpdates[i].subaccountId, collateralCoinId, batchUpdateData.perpetualAssetUpdates[i].crossCollateralAmount, batchUpdateData.perpetualAssetUpdates[i].positions);
            }
        }

        lastBatchId = batchId;
        batchSeqIds[batchId][seqInBatch] = true;
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

    function setStargateWithdraw(address _stargateWithdraw) external onlyOwner validAddress(_stargateWithdraw) {
        if (_stargateWithdraw == address(0)) revert ZeroAddressNotAllowed();
        stargateWithdraw = StargateWithdraw(_stargateWithdraw);
        emit StargateWithdrawUpdated(_stargateWithdraw);
    }
   
}
