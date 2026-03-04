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
import "../interfaces/IAsset.sol";
import "../margin/MarginAsset.sol";
import "../stargate/StargateWithdraw.sol";

/// @dev Legacy Asset implementation placeholder used for local upgrade testing.
/// NOTE: 当前实现仅作为占位符，直接复用最新版本的逻辑（包括 BLS）。
/// 如果你需要模拟真实的「老版本」，可以把历史版本的 Asset 源码拷贝到本文件，
/// 保持状态变量顺序与链上旧版本一致，再用本目录下的脚本做升级回归。
contract AssetV1 is OwnableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable, IAsset {
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

    struct SettlementValidator {
        bytes pk; // 128-byte G1 pubkey
        bool active;
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

    // BLS config for settlement operator (for now与新版本保持一致，方便脚本复用)
    bytes public settlementOperatorBlsPubkey;
    IBLS public bls;
    SettlementValidator[] public settlementValidators;
    uint256 public settlementActiveValidators;
    uint256 public settlementMinSignatures;

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

    // 这里为了简洁，只保留与测试流程相关的若干方法：
    // - setSigners
    // - setSettlementAddress
    // - setWithdrawOperator
    // - setMarginAsset
    // - setStargateWithdraw
    // - availableAmount（用于确保存储未损坏时可以调用）
    // - batchUpdate（直接复用新版本签名，包含 BLS 验证）

    function setSigners(address[] memory _signers) external onlyOwner {
        if (_signers.length == 0) revert ZeroAddressNotAllowed();
        for (uint256 i = 0; i < _signers.length; i++) {
            if (_signers[i] == address(0)) revert ZeroAddressNotAllowed();
        }
        signers = _signers;
        emit SignersUpdated(_signers);
    }

    function setSettlementAddress(address _settlementAddress) external onlyOwner validAddress(_settlementAddress) {
        settlementOperator = _settlementAddress;
        emit SettlementAddressUpdated(_settlementAddress);
    }

    function setWithdrawOperator(address _withdrawOperator) external onlyOwner validAddress(_withdrawOperator) {
        withdrawOperator = _withdrawOperator;
        emit WithdrawOperatorUpdated(_withdrawOperator);
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

    function setBls(address _bls) external onlyOwner validAddress(_bls) {
        bls = IBLS(_bls);
    }

    function setSettlementValidators(bytes[] calldata _pks, uint256 _minSignatures) external onlyOwner {
        uint256 len = _pks.length;
        if (len == 0) revert InvalidSettlementValidators();
        if (_minSignatures == 0 || _minSignatures > len) revert InvalidSettlementMinSignatures();

        delete settlementValidators;
        for (uint256 i = 0; i < len; i++) {
            settlementValidators.push(SettlementValidator({pk: _pks[i], active: true}));
        }
        settlementActiveValidators = len;
        settlementMinSignatures = _minSignatures;
    }

    function _collectSettlementPubkeys(bytes calldata bitmask) internal view returns (bytes[] memory) {
        uint256 total = settlementValidators.length;
        uint256 count;
        for (uint256 i = 0; i < total; i++) {
            if (_isBitSet(bitmask, i) && settlementValidators[i].active) {
                count++;
            }
        }
        if (count == 0) revert NoSettlementSigner();

        bytes[] memory pubkeys = new bytes[](count);
        uint256 pos;
        for (uint256 i = 0; i < total; i++) {
            if (_isBitSet(bitmask, i) && settlementValidators[i].active) {
                pubkeys[pos++] = settlementValidators[i].pk;
            }
        }
        return pubkeys;
    }

    function _isBitSet(bytes calldata mask, uint256 index) internal pure returns (bool) {
        uint256 byteIndex = index >> 3;
        if (byteIndex >= mask.length) return false;
        uint8 b = uint8(mask[byteIndex]);
        return (b & (1 << (index & 7))) != 0;
    }

    function availableAmount(bytes32) external pure returns (uint256) {
        // 简化：这里只返回 0，重点是验证调用不会因为升级而 revert。
        return 0;
    }

    /**
     * @notice Same signature as latest Asset.batchUpdate, 方便脚本在升级前后复用同一调用方式。
     * 实际逻辑与新版本基本一致（包含 BLS 验证），仅用于本地链自测。
     */
    function batchUpdate(
        uint256 batchId,
        int32 seqInBatch,
        uint256 antxChainHeight,
        BatchUpdateData memory batchUpdateData,
        bytes calldata blsSignature,
        bytes calldata bitmask
    ) public {
        if (address(bls) == address(0)) revert OnlySettlementOperator();
        if (settlementMinSignatures == 0 || settlementMinSignatures > settlementActiveValidators) {
            revert InvalidSettlementMinSignatures();
        }
        if (blsSignature.length != 256) revert OnlySettlementOperator();

        bytes32 messageHash = keccak256(abi.encode(batchId, seqInBatch, antxChainHeight, batchUpdateData));
        bytes[] memory pubkeys = _collectSettlementPubkeys(bitmask);
        if (pubkeys.length < settlementMinSignatures) revert InsufficientSettlementSignatures();
        bytes memory aggPk = bls.aggregatePubkeys(pubkeys);
        bytes memory h = bls.hashToPoint(messageHash);
        if (!bls.verifyAggregate(blsSignature, h, aggPk)) revert OnlySettlementOperator();

        // 下面保留与生产版本一致的 batchUpdate 状态更新逻辑（简化可根据需要裁剪）
        if (batchId == lastBatchId) {
            if (batchSeqIds[batchId][seqInBatch]) revert InvalidBatchId();
        } else if (batchId != lastBatchId + 1) {
            revert InvalidBatchId();
        }
        if (antxChainHeight <= lastAntxChainHeight) revert InvalidAntxChainHeight();
        if (marginAsset == address(0)) revert ZeroAddressNotAllowed();

        lastBatchId = batchId;
        batchSeqIds[batchId][seqInBatch] = true;
        lastBatchTime = block.timestamp;
        lastAntxChainHeight = antxChainHeight;
        hasBatchUpdate = true;
    }

    uint256[50] private __gap;
}

