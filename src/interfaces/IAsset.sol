// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "../margin/MarginAsset.sol";


interface IAsset {
    // Events
    event SignersUpdated(address[] signers);
    event SystemAddressUpdated(address indexed systemAddress);
    event LastBatchTimeUpdated(uint256 time);
    event UserWithdraw(uint256 clientOrderId,bytes32 indexed user, uint256 amount);
    event ForceWithdraw(bytes32 indexed user, uint256 amount);
    event BatchUpdated(uint256 batchId, uint256 antxChainHeight, uint256 time);
    event SettlementAddressUpdated(address indexed settlementAddress);
    event UpdateUserBalance(uint256 batchId, bytes32 indexed user, uint256 amount);
    event EmergencyWithdraw(address indexed to, uint256 amount);
    event WithdrawOperatorUpdated(address indexed withdrawOperator);
    event Ed25519OracleUpdated(address indexed ed25519Oracle);
    event MarginAssetAddressUpdated(address indexed marginAsset);
    event ExchangeInfoUpdated(uint64 exchangeId, uint32 stepSizeScale, uint32 tickSizeScale, uint256 oraclePrice, uint256 fundingIndex, MarginAsset.RiskTier[] riskTiers);
    event CoinInfoUpdated(uint64 coinId, string symbol, int32 stepSizeScale);
    event FundingIndexUpdated(uint64 exchangeId, int256 fundingIndex);
    event OraclePriceUpdated(uint64 exchangeId, uint256 oraclePrice, uint64 oracleTime);
    
    // Errors
    error InsufficientUserBalance(uint256 available, uint256 required);
    error InsufficientSystemBalance(address systemAddress, uint256 available, uint256 required);
    error ZeroAddressNotAllowed();
    error ZeroAmountNotAllowed();
    error FeeExceedsLimit(uint256 current, uint256 toAdd, uint256 limit);
    error TransferFailed();
    error TimeLockNotPassed();
    error InvalidTime(uint256 time);
    error UserAndAmountLengthNotMatch();
    error UserAndSignatureLengthNotMatch();
    error InvalidUserSignature();
    error InvalidToken();
    error InvalidAllSignersLength();
    error InvalidSignaturesLength();
    error SameSigner();
    error ExpiredTransaction();
    error InvalidSigner();
    error NotAllowedSigner();
    error OnlySettlementOperator();
    error OnlyWithdrawOperator();
    error InvalidBatchId();
    error NotAllowedToken(address token);
    error UserNotFound();
    error InvalidAntxChainHeight();

    enum SignatureType {
        ECDSA,
        ED25519
    }
    
    // State-changing functions
    function batchWithdraw(uint256 []memory clientOrderIds,uint64 []memory subaccountIds, uint256 []memory amounts,bytes[] memory signatures,SignatureType signatureType) external;
    function forceWithdraw(uint64 subaccountId,uint256 amount, SignatureType signatureType, bytes memory signatures) external;
    function setSigners(address[] memory _signers) external;
    function setSettlementAddress(address _settlementAddress) external;
    function setWithdrawOperator(address _withdrawOperator) external;
    function availableAmount(bytes32 user) external view returns (uint256);
    function availableAmountBySubAccountId(uint64 subAccountId) external view returns (uint256);
    function emergencyWithdraw(
        address token,
        address to, 
        uint256 amount,
        uint256 expireTime, 
        address[] memory allSigners,
        bytes[] memory signatures
    ) external;
}
