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

    function test_isAllowedSigner() public {
        // Check that initial signers are recognized
        assertTrue(asset.isAllowedSigner(signer1));
        assertTrue(asset.isAllowedSigner(signer2));
        
        // Check that other addresses are not recognized as signers
        assertFalse(asset.isAllowedSigner(user1));
        assertFalse(asset.isAllowedSigner(owner));
        assertFalse(asset.isAllowedSigner(address(0)));
    }

    function test_forceWithdraw_basic() public {
        // First give user1 some USDT
        vm.startPrank(owner);
        USDT.mint(user1, 1000);
        vm.stopPrank();
        
        // User1 transfers to asset contract
        vm.startPrank(user1);
        USDT.transfer(address(asset), 1000);
        vm.stopPrank();
        
        // Set up settlement contract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Add user balance through settlement
        vm.startPrank(address(settlement));
        asset.addUserBalance(user1, 1000);
        vm.stopPrank();
        
        // Set lastBatchTime to check timelock
        uint256 currentTime = block.timestamp;
        vm.startPrank(address(settlement));
        asset.setLastBatchTime(currentTime);
        vm.stopPrank();
        
        // Try to force withdraw before time lock - should fail
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.TimeLockNotPassed.selector));
        asset.forceWithdraw(500);
        vm.stopPrank();
        
        // Advance time past the time lock
        vm.warp(currentTime + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);
        
        // Now try to force withdraw - should succeed
        vm.startPrank(user1);
        vm.expectEmit(address(asset));
        emit IAsset.ForceWithdrawRequest(user1, 500);
        asset.forceWithdraw(500);
        vm.stopPrank();
        
        // Verify request was recorded
        assertEq(asset.forcedWithdrawalRequest(user1, 500), block.timestamp);
    }

    function test_forceWithdraw_zeroAmount() public {
        // Advance time past any potential time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);
        
        // Try force withdraw with zero amount
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.forceWithdraw(0);
        vm.stopPrank();
    }

    function test_forceWithdraw_duplicateRequest() public {
        // First give user1 some USDT
        vm.startPrank(owner);
        USDT.mint(user1, 1000);
        vm.stopPrank();
        
        // User1 transfers to asset contract
        vm.startPrank(user1);
        USDT.transfer(address(asset), 1000);
        vm.stopPrank();
        
        // Set up settlement contract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Add user balance through settlement
        vm.startPrank(address(settlement));
        asset.addUserBalance(user1, 1000);
        vm.stopPrank();
        
        // Set lastBatchTime 
        uint256 currentTime = block.timestamp;
        vm.startPrank(address(settlement));
        asset.setLastBatchTime(currentTime);
        vm.stopPrank();
        
        // Advance time past the time lock
        vm.warp(currentTime + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);
        
        // First force withdraw request
        vm.startPrank(user1);
        asset.forceWithdraw(500);
        
        // Try the same request again - should fail
        vm.expectRevert("REQUEST_ALREADY_PENDING");
        asset.forceWithdraw(500);
        vm.stopPrank();
    }

    function test_acceptForceWithdrawal() public {
        // First give user1 some USDT
        vm.startPrank(owner);
        USDT.mint(user1, 1000);
        vm.stopPrank();
        
        // User1 transfers to asset contract
        vm.startPrank(user1);
        USDT.transfer(address(asset), 1000);
        vm.stopPrank();
        
        // Set up settlement contract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Add user balance through settlement
        vm.startPrank(address(settlement));
        asset.addUserBalance(user1, 1000);
        vm.stopPrank();
        
        // Set lastBatchTime 
        uint256 currentTime = block.timestamp;
        vm.startPrank(address(settlement));
        asset.setLastBatchTime(currentTime);
        vm.stopPrank();
        
        // Advance time past the time lock
        vm.warp(currentTime + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);
        
        // First force withdraw request
        vm.startPrank(user1);
        asset.forceWithdraw(500);
        vm.stopPrank();
        
        // Try to accept force withdrawal for non-existing request
        vm.startPrank(address(settlement));
        vm.expectRevert("REQUEST_ALREADY_PENDING");
        asset.acceptForceWithdrawal(user1, 600); // Different amount
        
        // Accept the actual force withdrawal
        uint256 userBalanceBefore = USDT.balanceOf(user1);
        vm.expectEmit(address(asset));
        emit IAsset.AcceptForceWithdrawal(user1, 500);
        asset.acceptForceWithdrawal(user1, 500);
        vm.stopPrank();
        
        // Verify user received funds
        uint256 userBalanceAfter = USDT.balanceOf(user1);
        assertEq(userBalanceAfter - userBalanceBefore, 500);
    }

    function test_userBalance_operations() public {
        // Set up settlement contract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Initially balance should be zero
        assertEq(asset.userBalance(user1), 0);
        
        // Add user balance
        vm.startPrank(address(settlement));
        vm.expectEmit(address(asset));
        emit IAsset.AddUserBalance(user1, 1000);
        asset.addUserBalance(user1, 1000);
        vm.stopPrank();
        
        // Verify balance was added
        assertEq(asset.userBalance(user1), 1000);
        
        // Subtract user balance
        vm.startPrank(address(settlement));
        vm.expectEmit(address(asset));
        emit IAsset.SubUserBalance(user1, 300);
        asset.subUserBalance(user1, 300);
        vm.stopPrank();
        
        // Verify balance was subtracted
        assertEq(asset.userBalance(user1), 700);
    }

    function test_userWithdraw() public {
        // First give some USDT to contract
        vm.startPrank(owner);
        USDT.mint(address(asset), 1000);
        vm.stopPrank();
        
        // Set up settlement contract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Perform user withdraw
        vm.startPrank(address(settlement));
        uint256 userBalanceBefore = USDT.balanceOf(user1);
        vm.expectEmit(address(asset));
        emit IAsset.UserWithdraw(user1, 500);
        asset.userWithdraw(user1, 500);
        vm.stopPrank();
        
        // Verify user received funds
        uint256 userBalanceAfter = USDT.balanceOf(user1);
        assertEq(userBalanceAfter - userBalanceBefore, 500);
    }

    function test_riskMarginBalance() public {
        // Set up settlement contract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Initially risk margin balance should be zero
        assertEq(asset.riskMarginBalance(), 0);
        
        // Add risk margin balance
        vm.startPrank(address(settlement));
        vm.expectEmit(address(asset));
        emit IAsset.AddRiskMarginBalance(1000);
        asset.addRiskMarginBalance(1000);
        vm.stopPrank();
        
        // Verify balance was added
        assertEq(asset.riskMarginBalance(), 1000);
        
        // Subtract risk margin balance
        vm.startPrank(address(settlement));
        vm.expectEmit(address(asset));
        emit IAsset.SubRiskMarginBalance(300);
        asset.subRiskMarginBalance(300);
        vm.stopPrank();
        
        // Verify balance was subtracted
        assertEq(asset.riskMarginBalance(), 700);
    }

    function test_withdrawFee_signature_validation() public {
        // Set up settlement contract and add fee balance
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        vm.startPrank(address(settlement));
        asset.addFeeBalance(1000);
        vm.stopPrank();
        
        // Add USDT to asset
        vm.startPrank(owner);
        USDT.mint(address(asset), 1000);
        vm.stopPrank();
        
        // Prepare valid operation hash and signatures
        uint256 expireTime = block.timestamp + 1 days;
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                address(USDT),
                signer1,
                uint256(500),
                expireTime,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        
        // Case 1: Test with invalid signer
        uint256 randomKey = 123;
        address randomSigner = vm.addr(randomKey);
        bytes memory invalidSignature = signMessage(operationHash, randomKey);
        
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = randomSigner; // Not an allowed signer
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = invalidSignature;
        
        vm.expectRevert("not allowed signer");
        asset.withdrawFee(
            address(USDT),
            signer1,
            500,
            expireTime,
            allSigners,
            signatures
        );
        
        // Case 2: Test with signature mismatch
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        
        signatures[0] = signature1;
        signatures[1] = signature1; // Wrong signature for signer2
        
        vm.expectRevert("invalid signer");
        asset.withdrawFee(
            address(USDT),
            signer1,
            500,
            expireTime,
            allSigners,
            signatures
        );
        
        // Case 3: Test with expired time
        uint256 pastExpireTime = block.timestamp - 1;
        vm.expectRevert("expired transaction");
        asset.withdrawFee(
            address(USDT),
            signer1,
            500,
            pastExpireTime,
            allSigners,
            signatures
        );
        
        // Case 4: Test with wrong token address
        vm.expectRevert("invalid token");
        asset.withdrawFee(
            address(settlement), // Wrong token address
            signer1,
            500,
            expireTime,
            allSigners,
            signatures
        );
        
        // Case 5: Test with single signer (should fail)
        address[] memory singleSigner = new address[](1);
        singleSigner[0] = signer1;
        
        bytes[] memory singleSignature = new bytes[](1);
        singleSignature[0] = signature1;
        
        vm.expectRevert("invalid allSigners length");
        asset.withdrawFee(
            address(USDT),
            signer1,
            500,
            expireTime,
            singleSigner,
            singleSignature
        );
        
        // Case 6: Test with mismatched signature length
        address[] memory twoSigners = new address[](2);
        twoSigners[0] = signer1;
        twoSigners[1] = signer2;
        
        bytes[] memory threeSignatures = new bytes[](3);
        threeSignatures[0] = signature1;
        threeSignatures[1] = signature2;
        threeSignatures[2] = signature1;
        
        vm.expectRevert("invalid signatures length");
        asset.withdrawFee(
            address(USDT),
            signer1,
            500,
            expireTime,
            twoSigners,
            threeSignatures
        );
        
        // Case 7: Test with same signer twice
        address[] memory duplicateSigner = new address[](2);
        duplicateSigner[0] = signer1;
        duplicateSigner[1] = signer1;
        
        bytes[] memory duplicateSignature = new bytes[](2);
        duplicateSignature[0] = signature1;
        duplicateSignature[1] = signature1;
        
        vm.expectRevert("can not be same signer");
        asset.withdrawFee(
            address(USDT),
            signer1,
            500,
            expireTime,
            duplicateSigner,
            duplicateSignature
        );
    }

    function test_validAddress_modifier_comprehensive() public {
        // Test validAddress modifier on all functions with this modifier
        vm.startPrank(owner);
        
        // 1. Test constructor with zero address for USDT
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(0), signers);
        
        // 2. Test setSettlementContract with zero address
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSettlementContract(address(0));
        
        // 3. Test withdrawFee with zero address as recipient
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](2);
        uint256 expireTime = block.timestamp + 1 hours;
        
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.withdrawFee(address(USDT), address(0), 500, expireTime, allSigners, signatures);
        
        vm.stopPrank();
    }

    function test_validAmount_modifier_comprehensive() public {
        // Set up settlement contract first
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Test all functions with validAmount modifier using zero amount
        vm.startPrank(address(settlement));
        
        // 1. addUserBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.addUserBalance(user1, 0);
        
        // 2. subUserBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.subUserBalance(user1, 0);
        
        // 3. addFeeBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.addFeeBalance(0);
        
        // 4. addRiskMarginBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.addRiskMarginBalance(0);
        
        // 5. subRiskMarginBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.subRiskMarginBalance(0);
        
        // 6. userWithdraw
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.userWithdraw(user1, 0);
        
        // 7. acceptForceWithdrawal
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.acceptForceWithdrawal(user1, 0);
        
        vm.stopPrank();
        
        // 8. forceWithdraw (called by user)
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.forceWithdraw(0);
        vm.stopPrank();
    }

    function test_onlySettlement_modifier_comprehensive() public {
        // Set up settlement contract first
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        // Test all functions with onlySettlement modifier called by non-settlement account
        vm.startPrank(user1);
        
        // 1. setLastBatchTime
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.setLastBatchTime(block.timestamp);
        
        // 2. addUserBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.addUserBalance(user1, 100);
        
        // 3. subUserBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.subUserBalance(user1, 100);
        
        // 4. addFeeBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.addFeeBalance(100);
        
        // 5. addRiskMarginBalance
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.addRiskMarginBalance(100);
    }

    function test_withdraw_fee_multiple_signers() public {
        // Test withdrawFee with more than 2 signers to increase branch coverage
        
        // Setup with 3 signers
        address[] memory threeSigners = new address[](3);
        threeSigners[0] = signer1;
        threeSigners[1] = signer2;
        uint256 signer3PrivateKey = 3;
        address signer3 = vm.addr(signer3PrivateKey);
        threeSigners[2] = signer3;
        
        // Deploy new Asset contract with 3 signers
        vm.startPrank(owner);
        Asset assetWithThreeSigners = new Asset(address(USDT), threeSigners);
        
        // Add fee balance
        Settlement settlementForThreeSigners = new Settlement(address(assetWithThreeSigners), new address[](0));
        assetWithThreeSigners.setSettlementContract(address(settlementForThreeSigners));
        
        // Add some USDT
        USDT.mint(address(assetWithThreeSigners), 2000);
        vm.stopPrank();
        
        // Add fee balance
        vm.startPrank(address(settlementForThreeSigners));
        assetWithThreeSigners.addFeeBalance(1000);
        vm.stopPrank();
        
        // Prepare signatures from all 3 signers
        uint256 expireTime = block.timestamp + 1 days;
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                address(USDT),
                user1,
                uint256(500),
                expireTime,
                address(assetWithThreeSigners),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);
        
        // Create arrays for the call
        address[] memory allSigners = new address[](3);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        allSigners[2] = signer3;
        
        bytes[] memory signatures = new bytes[](3);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;
        
        // Execute withdrawFee with 3 signers
        uint256 userBalanceBefore = USDT.balanceOf(user1);
        
        assetWithThreeSigners.withdrawFee(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
        
        uint256 userBalanceAfter = USDT.balanceOf(user1);
        assertEq(userBalanceAfter - userBalanceBefore, 500);
        assertEq(assetWithThreeSigners.feeBalance(), 500);
    }

    function test_withdrawFee_comprehensive() public {
        // Set up settlement contract and add fee balance
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        
        vm.startPrank(address(settlement));
        asset.addFeeBalance(10000);
        vm.stopPrank();
        
        // Add USDT to the contract
        vm.startPrank(owner);
        USDT.mint(address(asset), 10000);
        vm.stopPrank();
        
        // Prepare for multi-signature checks
        uint256 expireTime = block.timestamp + 1 days;
        
        // Test with different numbers of signers
        
        // Condition 1: Test with exactly 2 signers (minimum required)
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                address(USDT),
                user1,
                uint256(1000),
                expireTime,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        
        address[] memory twoSigners = new address[](2);
        twoSigners[0] = signer1;
        twoSigners[1] = signer2;
        
        bytes[] memory twoSignatures = new bytes[](2);
        twoSignatures[0] = signature1;
        twoSignatures[1] = signature2;
        
        // This should succeed
        uint256 user1BalanceBefore = USDT.balanceOf(user1);
        asset.withdrawFee(
            address(USDT),
            user1,
            1000,
            expireTime,
            twoSigners,
            twoSignatures
        );
        uint256 user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 1000);
        
        // Condition 2: Test with a future expiry time
        uint256 futureTime = block.timestamp + 30 days;
        bytes32 futureHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                address(USDT),
                user1,
                uint256(500),
                futureTime,
                address(asset),
                block.chainid
            )
        );
        futureHash = MessageHashUtils.toEthSignedMessageHash(futureHash);
        
        bytes memory futureSig1 = signMessage(futureHash, signer1PrivateKey);
        bytes memory futureSig2 = signMessage(futureHash, signer2PrivateKey);
        
        twoSignatures[0] = futureSig1;
        twoSignatures[1] = futureSig2;
        
        user1BalanceBefore = USDT.balanceOf(user1);
        asset.withdrawFee(
            address(USDT),
            user1,
            500,
            futureTime,
            twoSigners,
            twoSignatures
        );
        user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 500);
        
        // Condition 3: Test with almost depleted fee balance
        bytes32 lastHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                address(USDT),
                user1,
                uint256(8499), // 10000 - 1000 - 500 = 8500 remaining, use 8499
                expireTime,
                address(asset),
                block.chainid
            )
        );
        lastHash = MessageHashUtils.toEthSignedMessageHash(lastHash);
        
        bytes memory lastSig1 = signMessage(lastHash, signer1PrivateKey);
        bytes memory lastSig2 = signMessage(lastHash, signer2PrivateKey);
        
        twoSignatures[0] = lastSig1;
        twoSignatures[1] = lastSig2;
        
        // This should succeed with just 1 remaining
        user1BalanceBefore = USDT.balanceOf(user1);
        asset.withdrawFee(
            address(USDT),
            user1,
            8499,
            expireTime,
            twoSigners,
            twoSignatures
        );
        user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 8499);
        
        // Verify fee balance is now 1
        assertEq(asset.feeBalance(), 1);
    }

    function test_userWithdraw_edge_cases() public {
        // Set up settlement contract
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        USDT.mint(address(asset), 10000);
        vm.stopPrank();
        
        // Test case 1: Regular withdrawal
        vm.startPrank(address(settlement));
        uint256 user1BalanceBefore = USDT.balanceOf(user1);
        vm.expectEmit(address(asset));
        emit IAsset.UserWithdraw(user1, 1000);
        asset.userWithdraw(user1, 1000);
        uint256 user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 1000);
        vm.stopPrank();
        
        // Test case 2: Mock failure in USDT transfer
        vm.mockCall(
            address(USDT),
            abi.encodeWithSelector(IERC20.transfer.selector),
            abi.encode(false)
        );
        
        vm.startPrank(address(settlement));
        vm.expectRevert(abi.encodeWithSelector(IAsset.TransferFailed.selector));
        asset.userWithdraw(user1, 1000);
        vm.stopPrank();
        
        // Clear mock and try a very large withdrawal (but within balance)
        vm.clearMockedCalls();
        
        // Test case 3: Large, but valid withdrawal
        vm.startPrank(address(settlement));
        user1BalanceBefore = USDT.balanceOf(user1);
        asset.userWithdraw(user1, 8000); // We should have 9000 left
        user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 8000);
        vm.stopPrank();
    }
}
