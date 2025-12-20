// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "../margin/MarginAsset.sol";


interface IAsset {
    // Events
    event SignersUpdated(address[] signers);
    event UserWithdraw(uint256 clientOrderId,bytes32 indexed user,bytes32 indexed recipient, uint256 amount, uint64 dstChainId);
    event CrossChainWithdraw(uint256 clientOrderId,bytes32 indexed user, bytes32 indexed recipient, uint256 amount, uint64 dstChainId);
    event ForceWithdraw(bytes32 indexed user, bytes32 indexed recipient, uint256 amount, uint64 dstChainId);
    event BatchUpdated(uint256 batchId, uint256 antxChainHeight, uint256 time);
    event SettlementAddressUpdated(address indexed settlementAddress);
    event USDCUpdated(address indexed USDC);
    event EmergencyWithdraw(address indexed to, uint256 amount);
    event WithdrawOperatorUpdated(address indexed withdrawOperator);
    event Ed25519OracleUpdated(address indexed ed25519Oracle);
    event MarginAssetAddressUpdated(address indexed marginAsset);
    event StargateWithdrawUpdated(address indexed stargateWithdraw);
    event ExchangeInfoUpdated(uint64 exchangeId, uint32 stepSizeScale, uint32 tickSizeScale, uint256 oraclePrice, uint256 fundingIndex, MarginAsset.RiskTier[] riskTiers);
    event CoinInfoUpdated(uint64 coinId, string symbol, uint32 stepSizeScale);
    event FundingIndexUpdated(uint64 exchangeId, int256 fundingIndex);
    event OraclePriceUpdated(uint64 exchangeId, uint256 oraclePrice, uint64 oracleTime);
    event SubaccountUpdated(uint64 subaccountId, bytes32 chainAddress, string clientAccountId, MarginAsset.TradeSetting[] tradeSettings);
    event PerpetualAssetUpdated(uint64 subaccountId, uint64 collateralCoinId, int64 crossCollateralAmount, MarginAsset.Position[] positions);
    
    // Errors
    error InsufficientUserBalance(uint256 available, uint256 required);
    error ZeroAddressNotAllowed();
    error ZeroAmountNotAllowed();
    error TimeLockNotPassed();
    error InvalidTime(uint256 time);
    error UserAndAmountLengthNotMatch();
    error UserAndSignatureLengthNotMatch();
    error InvalidUserSignature();
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
    error InvalidChainId();

    enum SignatureType {
        ECDSA,
        ED25519
    }
    
    // State-changing functions
    function batchWithdraw(uint256 []memory clientOrderIds,uint64 []memory subaccountIds,bytes32 []memory recipients,uint256 []memory expireTimes,uint256 []memory amounts,bytes[] memory signatures,uint64[] memory dstChainIds,SignatureType signatureType) external;
    function forceWithdraw(uint64 subaccountId,uint256 amount,uint256 expireTime,SignatureType signatureType,bytes memory signatures,uint64 dstChainId) external;
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
