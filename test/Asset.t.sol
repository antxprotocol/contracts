// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Asset} from "../src/Asset.sol";
import {IAsset} from "../src/interfaces/IAsset.sol";
import {Settlement} from "../src/Settlement.sol";
import {MockToken} from "../src/mock/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract AssetTest is Test {
    Asset public asset;
    Settlement public settlement;
    MockToken public USDT;
    address public owner;
    address public signer1;
    address public signer2;
    uint256 public signer1PrivateKey;
    uint256 public signer2PrivateKey;
    address internal user1 = address(0x5);
    address[] public signers;

    function setUp() public {
        // Initialize private keys and addresses
        signer1PrivateKey = 1;
        signer2PrivateKey = 2;
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        owner = vm.addr(999);  // Use a different private key for owner

        // Deploy mock USDT
        USDT = new MockToken("USDT", "USDT");

        // Initialize signers array
        signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        // Create batch submitters array
        address[] memory batchSubmitters = new address[](1);
        batchSubmitters[0] = owner;

        // Deploy contracts with proper owner
        vm.startPrank(owner);
        asset = new Asset(address(USDT), signers);
        settlement = new Settlement(address(asset), batchSubmitters);
        vm.stopPrank();
    }

    function signMessage(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function test_initial() public {
        assertEq(asset.getTotalBalance(), 0);
        assertEq(asset.owner(), owner);
        assertEq(asset.getUSDTAddress(), address(USDT));
        assertEq(asset.feeBalance(), 0);

        USDT.transfer(address(asset), 1000);
        assertEq(asset.getTotalBalance(), 1000);
    }

    function test_setSettlementContract() public {
        // not equal
        assertEq(asset.settlementContract(), address(0));

        // invalid owner
        vm.startPrank(signer1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer1));
        asset.setSettlementContract(address(settlement));
        // equal
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        assertEq(asset.settlementContract(), address(settlement));
    }

    function test_USDTBalance() public {
        // initial balance
        assertEq(USDT.balanceOf(address(asset)), 0);
        assertEq(asset.feeBalance(), 0);
        assertEq(asset.getTotalBalance(), 0);

        // deposit
        USDT.transfer(address(asset), 1000);
        assertEq(asset.feeBalance(), 0);
        assertEq(asset.getTotalBalance(), 1000);
    }

    function test_feeBalance() public {
        assertEq(asset.feeBalance(), 0);

        vm.startPrank(owner);

        // expect revert
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        settlement.addFeeBalanceForTest(1000);

        // set settlement contract
        asset.setSettlementContract(address(settlement));

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.feeBalance(), 1000);

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.feeBalance(), 2000);
        vm.stopPrank();
    }

    function test_feeWithdraw() public {
        assertEq(asset.feeBalance(), 0);

        vm.startPrank(owner);

        // expect revert
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        settlement.addFeeBalanceForTest(1000);

        // set settlement contract
        asset.setSettlementContract(address(settlement));

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.feeBalance(), 1000);

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.feeBalance(), 2000);

        // mint USDT to owner first
        USDT.mint(owner, 1000);
        console.log("owner USDT balance", USDT.balanceOf(owner));

        // mint USDT to asset
        USDT.mint(address(asset), 2000);
        assertEq(asset.getTotalBalance(), 2000);

        // prepare signatures
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        uint256 expireTime = block.timestamp + 1 hours;
        bytes32 operationHash = keccak256(abi.encodePacked(
            "WITHDDRAW_FEE",
            address(USDT),
            signer2,
            uint256(500),
            expireTime,
            address(asset),
            uint256(block.chainid)
        ));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // sign with signer1 and signer2
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(1, operationHash);
        signatures[0] = abi.encodePacked(r1, s1, v1);
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, operationHash);
        signatures[1] = abi.encodePacked(r2, s2, v2);

        // withdraw fee - transfer first then emit event
        vm.expectEmit(address(USDT));
        emit IERC20.Transfer(address(asset), signer2, 500);

        vm.expectEmit(address(asset));
        emit IAsset.WithdrawFee(signer2, 500);
        asset.withdrawFee(address(USDT), signer2, 500, expireTime, allSigners, signatures);

        assertEq(asset.feeBalance(), 1500);
        assertEq(USDT.balanceOf(signer2), 500);

        vm.stopPrank();
    }

    // Test error conditions in the constructor - invalid USDT address
    function test_constructor_invalidUSDT() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(0), signers);
        vm.stopPrank();
    }

    // Test error conditions in the constructor - empty signers array
    function test_constructor_emptySigners() public {
        vm.startPrank(owner);
        address[] memory emptySigners = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(USDT), emptySigners);
        vm.stopPrank();
    }

    // Test error conditions in the constructor - signers containing zero address
    function test_constructor_zeroAddressSigners() public {
        vm.startPrank(owner);
        address[] memory invalidSigners = new address[](3);
        invalidSigners[0] = signer1;
        invalidSigners[1] = address(0);  // Zero address
        invalidSigners[2] = signer2;
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(USDT), invalidSigners);
        vm.stopPrank();
    }

    // Test zero address error in setSettlementContract function
    function test_setSettlementContract_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSettlementContract(address(0));
        vm.stopPrank();
    }

    // Test the validAmount modifier - using zero amount
    function test_validAmount_zeroAmount() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Try to add fee balance with zero amount
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        settlement.addFeeBalanceForTest(0);
        vm.stopPrank();
        
        // Try to withdraw fee with zero amount
        vm.startPrank(owner);
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](2);
        uint256 expireTime = block.timestamp + 1 hours;
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.withdrawFee(address(USDT), signer2, 0, expireTime, allSigners, signatures);
        vm.stopPrank();
    }

    // Test the validAddress modifier in withdrawFee
    function test_withdrawFee_zeroAddress() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        settlement.addFeeBalanceForTest(1000);
        USDT.mint(address(asset), 1000);
        
        // Try to withdraw fee to zero address
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](2);
        uint256 expireTime = block.timestamp + 1 hours;
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.withdrawFee(address(USDT), address(0), 500, expireTime, allSigners, signatures);
        vm.stopPrank();
    }

    function test_withdrawFee_transferFailed() public {
        // Set up settlement contract and add fee balance for testing
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();

        // Add fee balance through settlement contract
        vm.prank(address(settlement));
        asset.addFeeBalance(1000);

        // Make USDT fail transfers
        vm.mockCall(
            address(USDT),
            abi.encodeWithSelector(IERC20.transfer.selector),
            abi.encode(false)
        );

        // Prepare signatures with two different signers
        uint256 expireTime = block.timestamp + 1 days;
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                address(USDT),
                signer1,
                uint256(1000),
                expireTime,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        // Call withdrawFee and expect it to revert due to transfer failure
        vm.expectRevert(IAsset.TransferFailed.selector);
        asset.withdrawFee(
            address(USDT),
            signer1,
            1000,
            expireTime,
            allSigners,
            signatures
        );

        // Verify fee balance remains unchanged
        assertEq(asset.feeBalance(), 1000);
    }

    // Test insufficient balance error when withdrawing fee
    function test_withdrawFee_insufficientBalance() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Add fee balance
        settlement.addFeeBalanceForTest(500);
        USDT.mint(address(asset), 1000);

        // prepare signatures
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        uint256 expireTime = block.timestamp + 1 hours;
        bytes32 operationHash = keccak256(abi.encodePacked(
            "WITHDDRAW_FEE",
            address(USDT),
            signer2,
            uint256(1000),
            expireTime,
            address(asset),
            uint256(block.chainid)
        ));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // sign with signer1 and signer2
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(1, operationHash);
        signatures[0] = abi.encodePacked(r1, s1, v1);
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, operationHash);
        signatures[1] = abi.encodePacked(r2, s2, v2);
        
        // Try to withdraw fee greater than the balance
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientFeeBalance.selector, 500, 1000));
        asset.withdrawFee(address(USDT), signer2, 1000, expireTime, allSigners, signatures);
        vm.stopPrank();
    }

    // Test the validTime modifier and setLastBatchTime function
    function test_validTime_zeroTime() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Try to set last batch time with zero value
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidTime.selector, 0));
        settlement.setLastBatchTimeForTest(0);
        vm.stopPrank();
    }

    function test_lastBatchTime() public {
        // Initial value should be 0
        assertEq(asset.lastBatchTime(), 0);
        
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Set a valid time
        uint256 newTime = block.timestamp;
        settlement.setLastBatchTimeForTest(newTime);
        
        // Check if time was updated
        assertEq(asset.lastBatchTime(), newTime);
        
        // Set another time and verify update
        uint256 newerTime = block.timestamp + 100;
        
        // Check for LastBatchTimeUpdated event
        vm.expectEmit(address(asset));
        emit IAsset.LastBatchTimeUpdated(newerTime);
        
        settlement.setLastBatchTimeForTest(newerTime);
        assertEq(asset.lastBatchTime(), newerTime);
        vm.stopPrank();
        
        // Try to call setLastBatchTime from non-settlement address
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.setLastBatchTime(block.timestamp);
        vm.stopPrank();
    }

    // Test that non-settlement contract cannot call setLastBatchTime
    function test_setLastBatchTime_nonSettlement() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.setLastBatchTime(block.timestamp);
        vm.stopPrank();
    }
}
