// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IStargate } from "@stargatefinance/stg-evm-v2/src/interfaces/IStargate.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SendParam, OFTReceipt} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {MessagingFee, MessagingReceipt} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

/**
 * @title StargateWithdraw
 * @notice Adapter contract for cross-chain withdrawals using Stargate protocol
 * @dev This contract handles cross-chain withdrawals for non-Arbitrum chains
 */
contract StargateWithdraw is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // Stargate contract
    IStargate public stargate;
    
    // USDC token address
    IERC20 public immutable usdc;

    // Mapping from chain ID to LayerZero endpoint ID
    mapping(uint256 => uint32) public chainIdToEndpointId;
    
    // Mapping to track if a chain is supported
    mapping(uint256 => bool) public supportedChains;

    // Events
    event CrossChainWithdrawInitiated(
        uint256 indexed clientOrderId,
        bytes32 indexed user,
        uint256 amount,
        uint256 sourceChainId,
        uint32 dstEid,
        bytes32 dstAddress,
        bytes32 guid
    );
    
    event StargatePoolUpdated(address indexed oldPool, address indexed newPool);
    event ChainEndpointUpdated(uint256 indexed chainId, uint32 endpointId);
    event ChainSupportUpdated(uint256 indexed chainId, bool supported);

    // Errors
    error InvalidChainId();
    error CrossChainNotSupported(uint256 chainId);
    error InvalidStargatePool();
    error InsufficientBalance();
    error TransferFailed();
    error InvalidEndpointId();

    modifier validChain(uint256 chainId) {
        if (chainId == 0) revert InvalidChainId();
        if (chainId == block.chainid) {
            revert CrossChainNotSupported(chainId);
        }
        if (!supportedChains[chainId]) {
            revert CrossChainNotSupported(chainId);
        }
        _;
    }

    constructor(
        address _usdc,
        address _stargate,
        address _owner
    ) Ownable(_owner) {
        if (_usdc == address(0)) revert InvalidChainId();
        if (_stargate == address(0)) revert InvalidStargatePool();
        
        usdc = IERC20(_usdc);
        stargate = IStargate(_stargate);
    }

    /**
     * @notice Execute cross-chain withdrawal using Stargate
     * @param clientOrderId Client order ID for tracking
     * @param user User address (bytes32 format)
     * @param amount Amount to withdraw
     * @param dstChainId Destination chain ID
     * @param dstAddress Destination address (bytes32 format)
     * @param minAmountLD Minimum amount to receive on destination (for slippage protection)
     * @param fee Messaging fee for LayerZero
     * @param refundAddress Address to refund excess fees
     */
    function crossChainWithdraw(
        uint256 clientOrderId,
        bytes32 user,
        uint256 amount,
        uint256 dstChainId,
        bytes32 dstAddress,
        uint256 minAmountLD,
        MessagingFee memory fee,
        address refundAddress
    ) external nonReentrant validChain(dstChainId) returns (bytes32 guid) {
        // Get destination endpoint ID
        uint32 dstEid = chainIdToEndpointId[dstChainId];
        if (dstEid == 0) revert InvalidEndpointId();

        // Transfer USDC from caller to this contract
        usdc.safeTransferFrom(msg.sender, address(this), amount);

        // Approve Stargate pool to spend USDC
        usdc.forceApprove(address(stargate), amount);

        // Prepare send parameters
       (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) = prepareRideBus(dstEid, amount, dstAddress);

        // Execute cross-chain send via Stargate
        (MessagingReceipt memory msgReceipt,,) = stargate.sendToken{value: valueToSend}(sendParam, messagingFee, refundAddress);

        // Reset approval
        usdc.forceApprove(address(stargate), 0);

        // Emit event
        emit CrossChainWithdrawInitiated(
            clientOrderId,
            user,
            amount,
            block.chainid,
            dstEid,
            dstAddress,
            msgReceipt.guid
        );

        return msgReceipt.guid;
    }

    /**
     * @notice Set Stargate pool address
     * @param _stargate New Stargate pool address
     */
    function setStargatePool(address _stargate) external onlyOwner {
        if (_stargate == address(0)) revert InvalidStargatePool();
        address oldPool = address(stargate);
        stargate = IStargate(_stargate);
        emit StargatePoolUpdated(oldPool, _stargate);
    }

    /**
     * @notice Set LayerZero endpoint ID for a chain
     * @param chainId Chain ID
     * @param endpointId LayerZero endpoint ID
     */
    function setChainEndpoint(uint256 chainId, uint32 endpointId) external onlyOwner {
        chainIdToEndpointId[chainId] = endpointId;
        emit ChainEndpointUpdated(chainId, endpointId);
    }

    /**
     * @notice Enable or disable support for a chain
     * @param chainId Chain ID
     * @param supported Whether the chain is supported
     */
    function setChainSupport(uint256 chainId, bool supported) external onlyOwner {
        if (chainId == block.chainid) {
            revert CrossChainNotSupported(chainId);
        }
        supportedChains[chainId] = supported;
        emit ChainSupportUpdated(chainId, supported);
    }

     function prepareTakeTaxi(
        uint32 _dstEid,
        uint256 _amount,
        bytes32 _receiver
    ) internal view returns (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) {
        sendParam = SendParam({
            dstEid: _dstEid,
            to: _receiver,
            amountLD: _amount,
            minAmountLD: _amount,
            extraOptions: new bytes(0),
            composeMsg: new bytes(0),
            oftCmd: new bytes(0)
        });

        (, , OFTReceipt memory receipt) = stargate.quoteOFT(sendParam);
        sendParam.minAmountLD = receipt.amountReceivedLD;

        messagingFee = stargate.quoteSend(sendParam, false);
        valueToSend = messagingFee.nativeFee;

        if (stargate.token() == address(0x0)) {
            valueToSend += sendParam.amountLD;
        }
    }

    function prepareRideBus(
        uint32 _dstEid,
        uint256 _amount,
        bytes32 _receiver
    ) internal view returns (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) {
        sendParam = SendParam({
            dstEid: _dstEid,
            to: _receiver,
            amountLD: _amount,
            minAmountLD: _amount,
            extraOptions: new bytes(0),
            composeMsg: new bytes(0),
            oftCmd: new bytes(1)
        });

        (, , OFTReceipt memory receipt) = stargate.quoteOFT(sendParam);
        sendParam.minAmountLD = receipt.amountReceivedLD;

        messagingFee = stargate.quoteSend(sendParam, false);
        valueToSend = messagingFee.nativeFee;

        if (stargate.token() == address(0x0)) {
            valueToSend += sendParam.amountLD;
        }
    }

    function addressToBytes32(address _addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(_addr)));
    }

    /**
     * @notice Emergency withdraw tokens (owner only)
     * @param token Token address
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function emergencyWithdraw(
        address token,
        address to,
        uint256 amount
    ) external onlyOwner {
        IERC20(token).safeTransfer(to, amount);
    }
}

