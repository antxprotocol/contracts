// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {StargateWithdraw} from "../src/stargate/StargateWithdraw.sol";
import {MockToken} from "../src/mock/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    SendParam,
    OFTReceipt,
    OFTLimit,
    OFTFeeDetail
} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {
    MessagingFee,
    MessagingReceipt
} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {Ticket, IStargate, StargateType} from "@stargatefinance/stg-evm-v2/src/interfaces/IStargate.sol";

// Mock Stargate contract for testing
contract MockStargate is IStargate {
    using SafeERC20 for IERC20;

    IERC20 public tokenContract;
    bool public shouldRevert;
    bool public shouldRevertOnQuote;
    uint256 public lastAmount;
    address public lastRefundAddress;

    constructor(address _token) {
        tokenContract = IERC20(_token);
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function setShouldRevertOnQuote(bool _shouldRevert) external {
        shouldRevertOnQuote = _shouldRevert;
    }

    function quoteOFT(SendParam calldata sendParam)
        external
        view
        returns (OFTLimit memory limit, OFTFeeDetail[] memory oftFeeDetails, OFTReceipt memory receipt)
    {
        if (shouldRevertOnQuote) {
            revert("MockStargate: quote failed");
        }
        // OFTReceipt has amountSentLD and amountReceivedLD fields
        receipt.amountSentLD = sendParam.amountLD;
        receipt.amountReceivedLD = sendParam.amountLD * 99 / 100; // Simulate 1% fee
        // Return empty limit and empty array for simplicity
        return (limit, oftFeeDetails, receipt);
    }

    function quoteSend(SendParam calldata sendParam, bool payInLzToken) external view returns (MessagingFee memory) {
        return MessagingFee({nativeFee: 0.001 ether, lzTokenFee: 0});
    }

    function sendToken(SendParam calldata sendParam, MessagingFee calldata messagingFee, address refundAddress)
        external
        payable
        returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt, Ticket memory ticket)
    {
        if (shouldRevert) {
            revert("MockStargate: sendToken failed");
        }

        // Transfer tokens from caller
        tokenContract.safeTransferFrom(msg.sender, address(this), sendParam.amountLD);

        lastAmount = sendParam.amountLD;
        lastRefundAddress = refundAddress;

        msgReceipt.guid = keccak256(abi.encodePacked(block.timestamp, msg.sender, sendParam.amountLD, sendParam.dstEid));
        msgReceipt.fee.nativeFee = messagingFee.nativeFee;
        msgReceipt.fee.lzTokenFee = messagingFee.lzTokenFee;

        oftReceipt.amountReceivedLD = sendParam.amountLD * 99 / 100;

        // Ticket structure is opaque, just return empty struct
        // The actual fields will be set by the Stargate contract
    }

    // Add token() function that returns the token address
    // This is needed for prepareRideBus to check if token is address(0)
    function token() external view returns (address) {
        return address(tokenContract);
    }

    // Required IStargate interface functions
    function approvalRequired() external pure returns (bool) {
        return true;
    }

    function oftVersion() external pure returns (bytes4 interfaceId, uint64 version) {
        return (bytes4(0), 0);
    }

    function sharedDecimals() external pure returns (uint8) {
        return 6;
    }

    function stargateType() external pure returns (StargateType) {
        return StargateType.OFT;
    }

    function send(SendParam calldata sendParam, MessagingFee calldata fee, address refundAddress)
        external
        payable
        returns (MessagingReceipt memory receipt, OFTReceipt memory oftReceipt)
    {
        // Not used in tests, but required by interface
        revert("MockStargate: send not implemented");
    }
}

contract StargateWithdrawTest is Test {
    StargateWithdraw public stargateWithdraw;
    MockToken public USDC;
    MockStargate public mockStargate;
    address public owner;
    address public user;

    receive() external payable {}

    uint256 constant CHAIN_ID_1 = 1; // Ethereum
    uint256 constant CHAIN_ID_2 = 42161; // Arbitrum
    uint256 constant CHAIN_ID_3 = 8453; // Base
    uint32 constant ENDPOINT_ID_1 = 30101;
    uint32 constant ENDPOINT_ID_2 = 30110;

    function setUp() public {
        owner = address(this);
        user = makeAddr("user");

        // Deploy mock USDC
        USDC = new MockToken("USDC", "USDC");

        // Deploy mock Stargate
        mockStargate = new MockStargate(address(USDC));

        // Deploy StargateWithdraw
        stargateWithdraw = new StargateWithdraw(address(USDC), address(mockStargate), owner);

        // Setup chain endpoints
        stargateWithdraw.setChainEndpoint(CHAIN_ID_1, ENDPOINT_ID_1);
        stargateWithdraw.setChainEndpoint(CHAIN_ID_2, ENDPOINT_ID_2);

        // Enable chains
        stargateWithdraw.setChainSupport(CHAIN_ID_1, true);
        stargateWithdraw.setChainSupport(CHAIN_ID_2, true);

        // Set test contract as asset so it can call crossChainWithdraw (onlyAsset modifier)
        stargateWithdraw.setAssetContract(address(this));
        // Mint USDC to test contract (asset) for crossChainWithdraw
        USDC.mint(address(this), 10000 ether);
        USDC.approve(address(stargateWithdraw), type(uint256).max);
        // Mint USDC to user for tests that need it
        USDC.mint(user, 10000 ether);
        vm.prank(user);
        USDC.approve(address(stargateWithdraw), type(uint256).max);
    }

    // ============ Constructor Tests ============

    function test_constructor_success() public {
        assertEq(address(stargateWithdraw.USDC()), address(USDC));
        assertEq(address(stargateWithdraw.stargate()), address(mockStargate));
        assertEq(stargateWithdraw.owner(), owner);
    }

    function test_constructor_zeroUSDC() public {
        vm.expectRevert(StargateWithdraw.InvalidUSDCAddress.selector);
        new StargateWithdraw(address(0), address(mockStargate), owner);
    }

    function test_constructor_zeroStargate() public {
        vm.expectRevert(StargateWithdraw.InvalidStargatePool.selector);
        new StargateWithdraw(address(USDC), address(0), owner);
    }

    // ============ Cross-Chain Withdraw Tests ============

    function test_crossChainWithdraw_success() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        uint256 balanceBefore = USDC.balanceOf(address(this));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);

        bytes32 guid = stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);

        assertTrue(guid != bytes32(0));
        assertEq(USDC.balanceOf(address(this)), balanceBefore - amount);
        assertEq(USDC.balanceOf(address(mockStargate)), amount);
    }

    function test_crossChainWithdraw_failureAndRefund() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        mockStargate.setShouldRevert(true);

        uint256 balanceBefore = USDC.balanceOf(address(this));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);

        bytes32 guid = stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);

        assertEq(guid, bytes32(0));
        assertEq(USDC.balanceOf(address(this)), balanceBefore);
        assertEq(USDC.balanceOf(address(stargateWithdraw)), 0);
    }

    function test_crossChainWithdraw_invalidChainId() public {
        SendParam memory dummySendParam;
        MessagingFee memory dummyMessagingFee;

        vm.expectRevert(StargateWithdraw.InvalidChainId.selector);
        stargateWithdraw.crossChainWithdraw(
            12345,
            bytes32(uint256(uint160(user))),
            1000 ether,
            0,
            bytes32(uint256(uint160(makeAddr("recipient")))),
            address(this),
            dummySendParam,
            dummyMessagingFee
        );
    }

    function test_crossChainWithdraw_sameChainId() public {
        SendParam memory dummySendParam;
        MessagingFee memory dummyMessagingFee;

        vm.expectRevert(abi.encodeWithSelector(StargateWithdraw.CrossChainNotSupported.selector, block.chainid));
        stargateWithdraw.crossChainWithdraw(
            12345,
            bytes32(uint256(uint160(user))),
            1000 ether,
            block.chainid,
            bytes32(uint256(uint160(makeAddr("recipient")))),
            address(this),
            dummySendParam,
            dummyMessagingFee
        );
    }

    function test_crossChainWithdraw_chainNotSupported() public {
        SendParam memory dummySendParam;
        MessagingFee memory dummyMessagingFee;

        vm.expectRevert(abi.encodeWithSelector(StargateWithdraw.CrossChainNotSupported.selector, CHAIN_ID_3));
        stargateWithdraw.crossChainWithdraw(
            12345,
            bytes32(uint256(uint160(user))),
            1000 ether,
            CHAIN_ID_3,
            bytes32(uint256(uint160(makeAddr("recipient")))),
            address(this),
            dummySendParam,
            dummyMessagingFee
        );
    }

    function test_crossChainWithdraw_invalidEndpointId() public {
        stargateWithdraw.setChainSupport(CHAIN_ID_3, true);

        SendParam memory dummySendParam;
        MessagingFee memory dummyMessagingFee;

        vm.expectRevert(StargateWithdraw.InvalidEndpointId.selector);
        stargateWithdraw.crossChainWithdraw(
            12345,
            bytes32(uint256(uint160(user))),
            1000 ether,
            CHAIN_ID_3,
            bytes32(uint256(uint160(makeAddr("recipient")))),
            address(this),
            dummySendParam,
            dummyMessagingFee
        );
    }

    function test_crossChainWithdraw_insufficientBalance() public {
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));
        // MockToken constructor mints 1e24 to deployer, and we mint 10000 ether; use more than total supply
        uint256 amount = 2 * 10**24;

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);
        vm.expectRevert();
        stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(
            12345,
            bytes32(uint256(uint160(user))),
            amount,
            CHAIN_ID_1,
            dstAddress,
            address(this),
            sendParam,
            messagingFee
        );
    }

    function test_crossChainWithdraw_emitsEvent() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);

        vm.expectEmit(true, true, false, false);
        emit StargateWithdraw.CrossChainWithdrawInitiated(
            12345,
            userBytes,
            amount,
            block.chainid,
            ENDPOINT_ID_1,
            dstAddress,
            bytes32(0)
        );
        bytes32 guid = stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);
        assertTrue(guid != bytes32(0));
    }

    function test_crossChainWithdraw_failureEmitsEvent() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        mockStargate.setShouldRevert(true);

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);

        vm.expectEmit(true, true, false, true);
        emit StargateWithdraw.CrossChainWithdrawFailed(12345, userBytes, amount, address(this));

        stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);
    }

    // ============ Admin Function Tests ============

    function test_setStargatePool_success() public {
        MockStargate newStargate = new MockStargate(address(USDC));

        vm.expectEmit(true, true, false, false);
        emit StargateWithdraw.StargatePoolUpdated(address(mockStargate), address(newStargate));

        stargateWithdraw.setStargatePool(address(newStargate));
        assertEq(address(stargateWithdraw.stargate()), address(newStargate));
    }

    function test_setStargatePool_zeroAddress() public {
        vm.expectRevert(StargateWithdraw.InvalidStargatePool.selector);
        stargateWithdraw.setStargatePool(address(0));
    }

    function test_setStargatePool_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        stargateWithdraw.setStargatePool(address(mockStargate));
    }

    function test_setChainEndpoint_success() public {
        vm.expectEmit(true, false, false, false);
        emit StargateWithdraw.ChainEndpointUpdated(CHAIN_ID_3, ENDPOINT_ID_1);

        stargateWithdraw.setChainEndpoint(CHAIN_ID_3, ENDPOINT_ID_1);
        assertEq(stargateWithdraw.chainIdToEndpointId(CHAIN_ID_3), ENDPOINT_ID_1);
    }

    function test_setChainEndpoint_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        stargateWithdraw.setChainEndpoint(CHAIN_ID_3, ENDPOINT_ID_1);
    }

    function test_setChainSupport_enable() public {
        vm.expectEmit(true, false, false, false);
        emit StargateWithdraw.ChainSupportUpdated(CHAIN_ID_3, true);

        stargateWithdraw.setChainSupport(CHAIN_ID_3, true);
        assertTrue(stargateWithdraw.supportedChains(CHAIN_ID_3));
    }

    function test_setChainSupport_disable() public {
        // First enable
        stargateWithdraw.setChainSupport(CHAIN_ID_3, true);
        assertTrue(stargateWithdraw.supportedChains(CHAIN_ID_3));

        // Then disable
        vm.expectEmit(true, false, false, false);
        emit StargateWithdraw.ChainSupportUpdated(CHAIN_ID_3, false);

        stargateWithdraw.setChainSupport(CHAIN_ID_3, false);
        assertFalse(stargateWithdraw.supportedChains(CHAIN_ID_3));
    }

    function test_setChainSupport_sameChainId() public {
        vm.expectRevert(abi.encodeWithSelector(StargateWithdraw.CrossChainNotSupported.selector, block.chainid));
        stargateWithdraw.setChainSupport(block.chainid, true);
    }

    function test_setChainSupport_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        stargateWithdraw.setChainSupport(CHAIN_ID_3, true);
    }

    function test_emergencyWithdraw_success() public {
        // Send some tokens to contract
        USDC.mint(address(stargateWithdraw), 1000 ether);

        address recipient = makeAddr("recipient");
        uint256 amount = 500 ether;

        stargateWithdraw.emergencyWithdraw(address(USDC), recipient, amount);

        assertEq(USDC.balanceOf(recipient), amount);
        assertEq(USDC.balanceOf(address(stargateWithdraw)), 1000 ether - amount);
    }

    function test_emergencyWithdraw_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert();
        stargateWithdraw.emergencyWithdraw(address(USDC), user, 100 ether);
    }

    // ============ Reentrancy Tests ============

    function test_crossChainWithdraw_reentrancyProtection() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);

        bytes32 guid = stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);

        assertTrue(guid != bytes32(0));
    }

    // ============ Edge Cases ============

    function test_crossChainWithdraw_maxAmount() public {
        uint256 maxAmount = 1000000 ether;
        USDC.mint(address(this), maxAmount);

        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), maxAmount, dstAddress);

        vm.deal(address(this), valueToSend);

        bytes32 guid = stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, maxAmount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);

        assertTrue(guid != bytes32(0));
    }

    function test_crossChainWithdraw_multipleChains() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        (uint256 valueToSend1, SendParam memory sendParam1, MessagingFee memory messagingFee1) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        (uint256 valueToSend2, SendParam memory sendParam2, MessagingFee memory messagingFee2) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_2), amount, dstAddress);

        vm.deal(address(this), valueToSend1 + valueToSend2);

        bytes32 guid1 = stargateWithdraw.crossChainWithdraw{
            value: valueToSend1
        }(1, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam1, messagingFee1);

        USDC.mint(address(this), amount);

        bytes32 guid2 = stargateWithdraw.crossChainWithdraw{
            value: valueToSend2
        }(2, userBytes, amount, CHAIN_ID_2, dstAddress, address(this), sendParam2, messagingFee2);

        assertTrue(guid1 != bytes32(0));
        assertTrue(guid2 != bytes32(0));
        assertTrue(guid1 != guid2);
    }

    // ============ prepareTakeTaxi Tests ============

    function test_prepareTakeTaxi_success() public {
        uint256 amount = 1000 ether;
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareTakeTaxi(uint64(CHAIN_ID_1), amount, dstAddress);

        assertEq(sendParam.dstEid, ENDPOINT_ID_1);
        assertEq(sendParam.amountLD, amount);
        assertEq(sendParam.to, dstAddress);
        assertEq(sendParam.oftCmd.length, 0); // prepareTakeTaxi uses empty oftCmd
        assertEq(messagingFee.nativeFee, 0.001 ether);
        assertEq(valueToSend, 0.001 ether);
    }

    function test_prepareTakeTaxi_invalidEndpointId() public {
        // Set chain support but no endpoint
        stargateWithdraw.setChainSupport(CHAIN_ID_3, true);

        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        vm.expectRevert(StargateWithdraw.InvalidEndpointId.selector);
        stargateWithdraw.prepareTakeTaxi(uint64(CHAIN_ID_3), 1000 ether, dstAddress);
    }

    function test_prepareTakeTaxi_vs_prepareRideBus_difference() public {
        uint256 amount = 1000 ether;
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        (uint256 valueToSend1, SendParam memory sendParam1, MessagingFee memory messagingFee1) =
            stargateWithdraw.prepareTakeTaxi(uint64(CHAIN_ID_1), amount, dstAddress);

        (uint256 valueToSend2, SendParam memory sendParam2, MessagingFee memory messagingFee2) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        // Main difference: oftCmd
        assertEq(sendParam1.oftCmd.length, 0);
        assertEq(sendParam2.oftCmd.length, 1);

        // Other values should be the same
        assertEq(valueToSend1, valueToSend2);
        assertEq(sendParam1.dstEid, sendParam2.dstEid);
        assertEq(sendParam1.amountLD, sendParam2.amountLD);
        assertEq(sendParam1.to, sendParam2.to);
    }

    function test_crossChainWithdraw_usingPrepareTakeTaxi() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        uint256 balanceBefore = USDC.balanceOf(address(this));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareTakeTaxi(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);

        bytes32 guid = stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);

        assertTrue(guid != bytes32(0));
        assertEq(USDC.balanceOf(address(this)), balanceBefore - amount);
        assertEq(USDC.balanceOf(address(mockStargate)), amount);
    }

    // ============ emergencyWithdrawETH Tests ============

    function test_emergencyWithdrawETH_success() public {
        // Send some ETH to contract
        vm.deal(address(stargateWithdraw), 1 ether);

        address recipient = makeAddr("recipient");
        uint256 amount = 0.5 ether;

        uint256 recipientBalanceBefore = recipient.balance;
        uint256 contractBalanceBefore = address(stargateWithdraw).balance;

        stargateWithdraw.emergencyWithdrawETH(recipient, amount);

        assertEq(recipient.balance, recipientBalanceBefore + amount);
        assertEq(address(stargateWithdraw).balance, contractBalanceBefore - amount);
    }

    function test_emergencyWithdrawETH_onlyOwner() public {
        vm.deal(address(stargateWithdraw), 1 ether);

        vm.prank(user);
        vm.expectRevert();
        stargateWithdraw.emergencyWithdrawETH(user, 0.1 ether);
    }

    function test_emergencyWithdrawETH_transferFailed() public {
        // Create a contract that rejects ETH transfers
        RejectETH rejector = new RejectETH();
        vm.deal(address(stargateWithdraw), 1 ether);

        vm.expectRevert(StargateWithdraw.TransferFailed.selector);
        stargateWithdraw.emergencyWithdrawETH(address(rejector), 0.5 ether);
    }

    // ============ receive() Tests ============

    function test_receive_eth() public {
        uint256 ethAmount = 1 ether;
        uint256 balanceBefore = address(stargateWithdraw).balance;

        // Send ETH directly to contract
        (bool success,) = address(stargateWithdraw).call{value: ethAmount}("");
        assertTrue(success);

        assertEq(address(stargateWithdraw).balance, balanceBefore + ethAmount);
    }

    function test_receive_eth_multiple() public {
        uint256 ethAmount1 = 0.5 ether;
        uint256 ethAmount2 = 0.3 ether;

        uint256 balanceBefore = address(stargateWithdraw).balance;

        // Send ETH multiple times
        (bool success1,) = address(stargateWithdraw).call{value: ethAmount1}("");
        assertTrue(success1);

        (bool success2,) = address(stargateWithdraw).call{value: ethAmount2}("");
        assertTrue(success2);

        assertEq(address(stargateWithdraw).balance, balanceBefore + ethAmount1 + ethAmount2);
    }


    function test_crossChainWithdraw_withPreFundedETH() public {
        uint256 amount = 1000 ether;
        bytes32 userBytes = bytes32(uint256(uint160(user)));
        bytes32 dstAddress = bytes32(uint256(uint160(makeAddr("recipient"))));

        (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee) =
            stargateWithdraw.prepareRideBus(uint64(CHAIN_ID_1), amount, dstAddress);

        vm.deal(address(this), valueToSend);

        bytes32 guid = stargateWithdraw.crossChainWithdraw{
            value: valueToSend
        }(12345, userBytes, amount, CHAIN_ID_1, dstAddress, address(this), sendParam, messagingFee);

        assertTrue(guid != bytes32(0));
    }
}

// Helper contract that rejects ETH transfers
contract RejectETH {
    receive() external payable {
        revert("RejectETH: I reject all ETH");
    }
}

