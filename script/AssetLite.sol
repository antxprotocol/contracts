// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// @deprecated AssetLite is no longer used for deployment.
// The full Asset contract now fits within EIP-170 limits (24,122 bytes with profile.deploy).
// This file is kept for historical reference only.
//
// Minimal Asset for BLS end-to-end testing on BSC Testnet.
// Implements the same batchUpdate signatures as Asset.sol so the relayer ABI is fully compatible.
// Strips everything not needed for BLS testing (Stargate, ECDSA multi-sig, margin calculations).

import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IBLS} from "../src/bls/BLS12381.sol";
import {MarginAsset} from "../src/margin/MarginAsset.sol";

contract AssetLite is OwnableUpgradeable, UUPSUpgradeable {
    // Identical to Asset.BatchUpdateData so the function selector & ABI encoding match exactly.
    struct BatchUpdateData {
        MarginAsset.Coin[] coinUpdates;
        MarginAsset.Exchange[] exchangeUpdates;
        MarginAsset.FundingIndex[] fundingIndexUpdates;
        MarginAsset.OraclePrice[] oraclePriceUpdates;
        MarginAsset.Subaccount[] subaccountUpdates;
        MarginAsset.PerpetualAsset[] perpetualAssetUpdates;
    }

    struct SettlementValidator {
        bytes pk;
        bool active;
    }

    // Public state expected by the relayer
    uint256 public lastBatchId;
    uint256 public lastAntxChainHeight;
    mapping(uint256 => mapping(int32 => bool)) public batchSeqIds;
    bool public hasBatchUpdate;
    address public settlementOperator;
    address public withdrawOperator;

    // BLS config
    IBLS public bls;
    SettlementValidator[] public settlementValidators;
    uint256 public settlementActiveValidators;
    uint256 public settlementMinSignatures;

    // Events (subset needed by relayer)
    event BatchUpdated(uint256 batchId, uint256 antxChainHeight, uint256 time);
    event SettlementAddressUpdated(address indexed settlementAddress);
    event WithdrawOperatorUpdated(address indexed withdrawOperator);

    // Errors (same selectors as IAsset so relayer error decoding works)
    error OnlySettlementOperator();
    error InvalidBatchId();
    error InvalidAntxChainHeight();
    error InvalidSettlementMinSignatures();
    error InvalidSettlementValidators();
    error NoSettlementSigner();
    error InsufficientSettlementSignatures();
    error BlsMultiSigRequired();
    error ZeroAddressNotAllowed();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address, uint64) external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    // ── batchUpdate (4-param, delegates to 6-param) ─────────────────────────
    function batchUpdate(
        uint256 batchId,
        int32 seqInBatch,
        uint256 antxChainHeight,
        BatchUpdateData memory batchUpdateData
    ) public {
        batchUpdate(batchId, seqInBatch, antxChainHeight, batchUpdateData, "", "");
    }

    // ── batchUpdate (6-param, BLS validation) ───────────────────────────────
    function batchUpdate(
        uint256 batchId,
        int32 seqInBatch,
        uint256 antxChainHeight,
        BatchUpdateData memory batchUpdateData,
        bytes memory blsSignature,
        bytes memory bitmask
    ) public {
        if (address(bls) != address(0)) {
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
        } else {
            revert BlsMultiSigRequired();
        }

        if (batchId == lastBatchId) {
            if (batchSeqIds[batchId][seqInBatch]) revert InvalidBatchId();
        } else if (batchId != lastBatchId + 1) {
            revert InvalidBatchId();
        }
        if (antxChainHeight <= lastAntxChainHeight) revert InvalidAntxChainHeight();

        if (!hasBatchUpdate) hasBatchUpdate = true;
        lastBatchId = batchId;
        batchSeqIds[batchId][seqInBatch] = true;
        lastAntxChainHeight = antxChainHeight;
        emit BatchUpdated(batchId, antxChainHeight, block.timestamp);
    }

    // ── BLS setters ─────────────────────────────────────────────────────────
    function setBls(address _bls) external onlyOwner {
        if (_bls == address(0)) revert ZeroAddressNotAllowed();
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

    function setSettlementAddress(address _addr) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddressNotAllowed();
        settlementOperator = _addr;
        emit SettlementAddressUpdated(_addr);
    }

    function setWithdrawOperator(address _addr) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddressNotAllowed();
        withdrawOperator = _addr;
        emit WithdrawOperatorUpdated(_addr);
    }

    // ── Internal helpers ─────────────────────────────────────────────────────
    function _collectSettlementPubkeys(bytes memory bitmask) internal view returns (bytes[] memory) {
        uint256 total = settlementValidators.length;
        uint256 count;
        for (uint256 i = 0; i < total; i++) {
            if (_isBitSet(bitmask, i) && settlementValidators[i].active) count++;
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

    function _isBitSet(bytes memory mask, uint256 index) internal pure returns (bool) {
        uint256 byteIndex = index >> 3;
        if (byteIndex >= mask.length) return false;
        return (uint8(mask[byteIndex]) & (1 << (index & 7))) != 0;
    }
}
