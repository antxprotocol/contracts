// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IStargate, StargateType, Ticket} from "@stargatefinance/stg-evm-v2/src/interfaces/IStargate.sol";
import {
    MessagingFee,
    MessagingReceipt,
    OFTReceipt,
    SendParam,
    OFTLimit,
    OFTFeeDetail
} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

 import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
 import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

 contract AntStrargateAdapter is IStargate {
    using SafeERC20 for IERC20;
    IStargate public immutable stargate;

    constructor(
        address _stargate // local endpoint address
    ) {
        stargate = IStargate(_stargate);
    }

    function approvalRequired() external view returns (bool) {
        return stargate.approvalRequired();
    }

    function oftVersion() external view returns (bytes4 interfaceId, uint64 version) {
        return stargate.oftVersion();
    }

    function quoteOFT(SendParam calldata _sendParam)
        external
        view
        returns (OFTLimit memory limit, OFTFeeDetail[] memory oftFeeDetails, OFTReceipt memory receipt)
    {
        return stargate.quoteOFT(_sendParam);
    }

    function quoteSend(SendParam calldata _sendParam, bool _payInLzToken)
        external
        view
        returns (MessagingFee memory fee)
    {
        return stargate.quoteSend(_sendParam, _payInLzToken);
    }

    function send(SendParam calldata _sendParam, MessagingFee calldata _fee, address _refundAddress)
        external
        payable
        returns (MessagingReceipt memory receipt, OFTReceipt memory oftReceipt)
    {
        address stargateToken = stargate.token();
        if (stargateToken != address(0)) {
            IERC20(stargateToken).safeTransferFrom(msg.sender, address(this), _sendParam.amountLD);
            IERC20(stargateToken).forceApprove(address(stargate), _sendParam.amountLD);
        }
        (receipt, oftReceipt) = stargate.send{value: msg.value}(_sendParam, _fee, _refundAddress);
        if (stargateToken != address(0)) {
            IERC20(stargateToken).forceApprove(address(stargate), 0);
        }
        return (receipt, oftReceipt);
    }

    function sendToken(SendParam calldata _sendParam, MessagingFee calldata _fee, address _refundAddress)
        external
        payable
        returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt, Ticket memory ticket)
    {
        address stargateToken = stargate.token();
        if (stargateToken != address(0)) {
            IERC20(stargateToken).safeTransferFrom(msg.sender, address(this), _sendParam.amountLD);
            IERC20(stargateToken).forceApprove(address(stargate), _sendParam.amountLD);
        }
        (msgReceipt, oftReceipt, ticket) = stargate.sendToken{value: msg.value}(_sendParam, _fee, _refundAddress);
        if (stargateToken != address(0)) {
            IERC20(stargateToken).forceApprove(address(stargate), 0);
        }
        return (msgReceipt, oftReceipt, ticket);
    }

    function sharedDecimals() external view returns (uint8) {
        return stargate.sharedDecimals();
    }

    function stargateType() external pure returns (StargateType) {
        return StargateType.OFT;
    }

    function token() external view returns (address) {
        return stargate.token();
    }

    function prepareTakeTaxi(uint32 _dstEid, uint256 _amount, address _receiver)
        external
        view
        returns (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee)
    {
        sendParam = SendParam({
            dstEid: _dstEid,
            to: addressToBytes32(_receiver),
            amountLD: _amount,
            minAmountLD: _amount,
            extraOptions: new bytes(0),
            composeMsg: new bytes(0),
            oftCmd: new bytes(0)
        });

        (,, OFTReceipt memory receipt) = stargate.quoteOFT(sendParam);
        sendParam.minAmountLD = receipt.amountReceivedLD;

        messagingFee = stargate.quoteSend(sendParam, false);
        valueToSend = messagingFee.nativeFee;

        if (stargate.token() == address(0x0)) {
            valueToSend += sendParam.amountLD;
        }
    }

    function prepareRideBus(uint32 _dstEid, uint256 _amount, address _receiver)
        external
        view
        returns (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee)
    {
        sendParam = SendParam({
            dstEid: _dstEid,
            to: addressToBytes32(_receiver),
            amountLD: _amount,
            minAmountLD: _amount,
            extraOptions: new bytes(0),
            composeMsg: new bytes(0),
            oftCmd: new bytes(1)
        });

        (,, OFTReceipt memory receipt) = stargate.quoteOFT(sendParam);
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
}
