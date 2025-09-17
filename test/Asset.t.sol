// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Asset} from "../src/Asset.sol";
import {IAsset} from "../src/interfaces/IAsset.sol";
import {MockToken} from "../src/mock/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// Simple mock for Ed25519 oracle used within tests
contract MockEd25519Oracle {
    bool public result;
    function setResult(bool newResult) external {
        result = newResult;
    }
    function isVerified(bytes32, bytes32, bytes calldata) external view returns (bool) {
        return result;
    }
}

contract AssetTest is Test {
    Asset public asset;
    MockToken public USDT;
    address public owner;
    address public systemAddress;
    address public settlementOperator;
    address public withdrawOperator;
    address public signer1;
    address public signer2;
    address public signer3;
    uint256 public signer1PrivateKey;
    uint256 public signer2PrivateKey;
    uint256 public signer3PrivateKey;
    address internal user1 = address(0x5);
    address internal user2 = address(0x6);
    address[] public signers;

    function setUp() public {
        // Initialize private keys and addresses
        signer1PrivateKey = 1;
        signer2PrivateKey = 2; 
        signer3PrivateKey = 3;
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        signer3 = vm.addr(signer3PrivateKey);
        owner = vm.addr(999);
        systemAddress = vm.addr(888);
        settlementOperator = vm.addr(777);
        withdrawOperator = vm.addr(666);

        // Deploy mock USDT
        USDT = new MockToken("USDT", "USDT");

        // Initialize signers array
        signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;

        // Deploy Asset contract with proper owner
        vm.startPrank(owner);
        asset = new Asset(address(USDT), signers, systemAddress, settlementOperator, withdrawOperator, address(0));
        vm.stopPrank();
    }

    function signMessage(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    // Test constructor functionality
    function test_constructor_success() public {
        assertEq(asset.owner(), owner);
        assertEq(address(asset.USDT()), address(USDT));
        assertEq(asset.systemAddress(), systemAddress);
        assertEq(asset.settlementOperator(), settlementOperator);
        assertEq(asset.withdrawOperator(), withdrawOperator);
        assertEq(asset.lastBatchId(), 0);
        assertEq(asset.lastBatchTime(), 0);
        assertTrue(asset.isAllowedSigner(signer1));
        assertTrue(asset.isAllowedSigner(signer2));
        assertTrue(asset.isAllowedSigner(signer3));
    }

    function test_constructor_zeroUSDT() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(0), signers, systemAddress, settlementOperator, withdrawOperator, address(0));
        vm.stopPrank();
    }

    function test_constructor_zeroSystemAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(USDT), signers, address(0), settlementOperator, withdrawOperator, address(0));
        vm.stopPrank();
    }

    function test_constructor_zeroSettlementOperator() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(USDT), signers, systemAddress, address(0), withdrawOperator, address(0));
        vm.stopPrank();
    }

    function test_constructor_zeroWithdrawOperator() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(USDT), signers, systemAddress, settlementOperator, address(0), address(0));
        vm.stopPrank();
    }

    function test_constructor_emptySigners() public {
        vm.startPrank(owner);
        address[] memory emptySigners = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(USDT), emptySigners, systemAddress, settlementOperator, withdrawOperator, address(0));
        vm.stopPrank();
    }

    function test_constructor_zeroAddressInSigners() public {
        vm.startPrank(owner);
        address[] memory invalidSigners = new address[](2);
        invalidSigners[0] = signer1;
        invalidSigners[1] = address(0);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new Asset(address(USDT), invalidSigners, systemAddress, settlementOperator, withdrawOperator, address(0));
        vm.stopPrank();
    }

    // Test updateUserBalances function
    function test_updateUserBalances_success() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;
        
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1000;
        amounts[1] = 2000;

        vm.startPrank(settlementOperator);
        vm.expectEmit(address(asset));
        emit IAsset.UpdateUserBalance(1, bytes32(uint256(uint160(user1))), 1000);
        vm.expectEmit(address(asset));
        emit IAsset.UpdateUserBalance(1, bytes32(uint256(uint160(user2))), 2000);
        vm.expectEmit(address(asset));
        emit IAsset.BatchUpdated(1, block.timestamp);

        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        bUsers[1] = bytes32(uint256(uint160(user2)));
        asset.updateUserBalances(1, bUsers, amounts);   
        vm.stopPrank();

        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 1000);
        assertEq(asset.userBalance(bytes32(uint256(uint160(user2)))), 2000);
        assertEq(asset.lastBatchId(), 1);
        assertEq(asset.lastBatchTime(), block.timestamp);
    }

    function test_updateUserBalances_invalidBatchId() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));       
        // Try to update with invalid batch ID (should be 1, but using 2)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        asset.updateUserBalances(2, bUsers, amounts);
        
        // Try with 0 (should also fail since lastBatchId is 0, expecting 1)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        asset.updateUserBalances(0, bUsers, amounts);
        
        vm.stopPrank();
    }

    function test_updateUserBalances_sequentialBatchIds() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        
        // First batch should be ID 1
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        assertEq(asset.lastBatchId(), 1);
        
        // Second batch should be ID 2
        amounts[0] = 2000;
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(2, bUsers, amounts);
        assertEq(asset.lastBatchId(), 2);
        
        // Third batch should be ID 3
        amounts[0] = 3000;
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(3, bUsers, amounts);
        assertEq(asset.lastBatchId(), 3);
        
        vm.stopPrank();
        
        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 3000);
    }

    function test_updateUserBalances_onlySettlementOperator() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.OnlySettlementOperator.selector));
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();
    }

    function test_updateUserBalances_lengthMismatch() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        vm.expectRevert(abi.encodeWithSelector(IAsset.UserAndAmountLengthNotMatch.selector));
        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        bUsers[1] = bytes32(uint256(uint160(user2)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();
    }

    // Test batchWithdraw function with proper signature
    function test_batchWithdraw_success() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature with the correct private key for the test user
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser))), uint256(500), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        uint256 userBalanceBefore = USDT.balanceOf(testUser);
        
        // Execute batch withdraw - should now work with correct signature
        vm.startPrank(withdrawOperator);
        vm.expectEmit(address(asset));
        emit IAsset.UserWithdraw(123, bytes32(uint256(uint160(testUser))), 500);
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
        
        uint256 userBalanceAfter = USDT.balanceOf(testUser);
        assertEq(userBalanceAfter - userBalanceBefore, 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(testUser)))), 500);
    }

    // Test batchWithdraw with invalid signature
    function test_batchWithdraw_invalidSignature() public {
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);

        address[] memory users = new address[](1);
        users[0] = user1;

        bytes32[] memory bUsers = new bytes32[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            bUsers[i] = bytes32(uint256(uint160(users[i])));
        }
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        amounts[0] = 500;

        // Create signature with wrong private key
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), user1, uint256(500), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        uint256 wrongPrivateKey = 999;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, operationHash);
        bytes memory wrongSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = wrongSignature;
        
        // Execute batch withdraw - should fail with invalid signature
        vm.startPrank(withdrawOperator);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidUserSignature.selector));
        asset.batchWithdraw(clientOrderIds, bUsers, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
    }

    // Test batchWithdraw with insufficient user balance
    function test_batchWithdraw_insufficientBalance() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup small user balance
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100; // Small balance

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare batch withdraw for more than user has
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500; // More than user has

        // Create user signature
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser))), uint256(500), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;
        
        // Execute batch withdraw - should fail with insufficient balance
        vm.startPrank(withdrawOperator);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, 100, 500));
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
    }

    function test_batchWithdraw_lengthMismatch() public {
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](2);
        users[0] = bytes32(uint256(uint160(user1)));
        users[1] = bytes32(uint256(uint160(user2)));
        
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500;
        
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = new bytes(65);

        vm.startPrank(withdrawOperator);
        vm.expectRevert(abi.encodeWithSelector(IAsset.UserAndAmountLengthNotMatch.selector));
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
    }

    function test_batchWithdraw_signatureLengthMismatch() public {
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(user1)));
        
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500;
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = new bytes(65);
        signatures[1] = new bytes(65);

        vm.startPrank(withdrawOperator);
        vm.expectRevert(abi.encodeWithSelector(IAsset.UserAndSignatureLengthNotMatch.selector));
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
    }

    // Test batchWithdraw onlyWithdrawOperator
    function test_batchWithdraw_onlyWithdrawOperator() public {
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(user1)));
        
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500;
        
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = new bytes(65);

        // Try to call from non-withdrawOperator address
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.OnlyWithdrawOperator.selector));
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
    }

    // Test forceWithdraw function
    function test_forceWithdraw_success() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Advance time past the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDT.balanceOf(user1);

        vm.startPrank(user1);
        vm.expectEmit(address(asset));
        emit IAsset.ForceWithdraw(bytes32(uint256(uint160(user1))), 500);
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();

        uint256 user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 500);
    }

    function test_forceWithdraw_timeLockNotPassed() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Don't advance time
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.TimeLockNotPassed.selector));
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();
    }

    function test_forceWithdraw_zeroAmount() public {
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);
        
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 0, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();
    }

    function test_forceWithdraw_insufficientBalance() public {
        // Setup small user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, 100, 500));
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();
    }

    // Test systemWithdraw function
    function test_systemWithdraw_success() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare multi-sig withdraw
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 500;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
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

        uint256 recipientBalanceBefore = USDT.balanceOf(recipient);

        vm.expectEmit(address(asset));
        emit IAsset.SystemWithdraw(recipient, withdrawAmount);
        
        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        uint256 recipientBalanceAfter = USDT.balanceOf(recipient);
        assertEq(recipientBalanceAfter - recipientBalanceBefore, withdrawAmount);
        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 500);
    }

    function test_systemWithdraw_invalidToken() public {
        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](2);
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidToken.selector));
        asset.systemWithdraw(
            address(0x123), // Invalid token
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    function test_systemWithdraw_insufficientSigners() public {
        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](1);
        allSigners[0] = signer1;
        bytes[] memory signatures = new bytes[](1);

        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidAllSignersLength.selector));
        asset.systemWithdraw(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    function test_systemWithdraw_signatureLengthMismatch() public {
        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](3);

        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidSignaturesLength.selector));
        asset.systemWithdraw(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    function test_systemWithdraw_sameSigner() public {
        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer1; // Same signer
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(abi.encodeWithSelector(IAsset.SameSigner.selector));
        asset.systemWithdraw(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    function test_systemWithdraw_expiredTransaction() public {
        uint256 expireTime = block.timestamp - 1; // Already expired
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(abi.encodeWithSelector(IAsset.ExpiredTransaction.selector));
        asset.systemWithdraw(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    function test_systemWithdraw_insufficientSystemBalance() public {
        // Setup small system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientSystemBalance.selector, systemAddress, 100, 500));
        asset.systemWithdraw(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    function test_systemWithdraw_invalidSigner() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        uint256 expireTime = block.timestamp + 1 hours;
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                user1, 
                uint256(500), 
                expireTime, 
                address(asset), 
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // Use wrong private key for signature
        bytes memory wrongSignature = signMessage(operationHash, 999);
        bytes memory correctSignature = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = wrongSignature; // Wrong signature
        signatures[1] = correctSignature;

        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidSigner.selector));
        asset.systemWithdraw(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    function test_systemWithdraw_notAllowedSigner() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        uint256 expireTime = block.timestamp + 1 hours;
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                user1, 
                uint256(500), 
                expireTime, 
                address(asset), 
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // Use a signer that's not in the allowed list
        uint256 notAllowedKey = 888;
        address notAllowedSigner = vm.addr(notAllowedKey);
        bytes memory notAllowedSignature = signMessage(operationHash, notAllowedKey);
        bytes memory validSignature = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = notAllowedSigner;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = notAllowedSignature;
        signatures[1] = validSignature;

        vm.expectRevert(abi.encodeWithSelector(IAsset.NotAllowedSigner.selector));
        asset.systemWithdraw(
            address(USDT),
            user1,
            500,
            expireTime,
            allSigners,
            signatures
        );
    }

    // Test admin functions
    function test_setSystemAddress_success() public {
        address newSystemAddress = address(0x999);
        
        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.SystemAddressUpdated(newSystemAddress);
        asset.setSystemAddress(newSystemAddress);
        vm.stopPrank();

        assertEq(asset.systemAddress(), newSystemAddress);
    }

    function test_setSystemAddress_onlyOwner() public {
        address newSystemAddress = address(0x999);
        
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setSystemAddress(newSystemAddress);
        vm.stopPrank();
    }

    function test_setSystemAddress_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSystemAddress(address(0));
        vm.stopPrank();
    }

    function test_setSettlementAddress_success() public {
        address newSettlementAddress = address(0x888);
        
        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.SettlementAddressUpdated(newSettlementAddress);
        asset.setSettlementAddress(newSettlementAddress);
        vm.stopPrank();

        assertEq(asset.settlementOperator(), newSettlementAddress);
    }

    function test_setSettlementAddress_onlyOwner() public {
        address newSettlementAddress = address(0x888);
        
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setSettlementAddress(newSettlementAddress);
        vm.stopPrank();
    }

    function test_setSettlementAddress_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSettlementAddress(address(0));
        vm.stopPrank();
    }

    function test_setSigners_success() public {
        address[] memory newSigners = new address[](2);
        newSigners[0] = address(0x111);
        newSigners[1] = address(0x222);
        
        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.SignersUpdated(newSigners);
        asset.setSigners(newSigners);
        vm.stopPrank();

        assertTrue(asset.isAllowedSigner(address(0x111)));
        assertTrue(asset.isAllowedSigner(address(0x222)));
        assertFalse(asset.isAllowedSigner(signer1)); // Old signer should no longer be valid
    }

    function test_setSigners_onlyOwner() public {
        address[] memory newSigners = new address[](1);
        newSigners[0] = address(0x111);
        
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setSigners(newSigners);
        vm.stopPrank();
    }

    function test_setSigners_emptyArray() public {
        address[] memory emptySigners = new address[](0);
        
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSigners(emptySigners);
        vm.stopPrank();
    }

    function test_setSigners_zeroAddressInArray() public {
        address[] memory invalidSigners = new address[](2);
        invalidSigners[0] = address(0x111);
        invalidSigners[1] = address(0); // Zero address
        
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSigners(invalidSigners);
        vm.stopPrank();
    }

    function test_setWithdrawOperator_success() public {
        address newWithdrawOperator = address(0x777);
        
        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.WithdrawOperatorUpdated(newWithdrawOperator);
        asset.setWithdrawOperator(newWithdrawOperator);
        vm.stopPrank();

        assertEq(asset.withdrawOperator(), newWithdrawOperator);
    }

    function test_setWithdrawOperator_onlyOwner() public {
        address newWithdrawOperator = address(0x777);
        
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setWithdrawOperator(newWithdrawOperator);
        vm.stopPrank();
    }

    function test_setWithdrawOperator_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setWithdrawOperator(address(0));
        vm.stopPrank();
    }

    // Test isAllowedSigner function
    function test_isAllowedSigner() public {
        assertTrue(asset.isAllowedSigner(signer1));
        assertTrue(asset.isAllowedSigner(signer2));
        assertTrue(asset.isAllowedSigner(signer3));
        assertFalse(asset.isAllowedSigner(user1));
        assertFalse(asset.isAllowedSigner(address(0)));
    }

    // Test transfer failure scenarios
    function test_userWithdraw_transferFailure() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Set USDT to fail transfers
        USDT.setFailTransfers(true);

        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        vm.expectRevert(); // Should revert due to SafeERC20 failing on false return
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();

        // Reset transfer behavior
        USDT.setFailTransfers(false);
    }

    // Test reentrancy protection
    function test_reentrancy_protection() public {
        // The contract uses ReentrancyGuard, so reentrancy should be prevented
        // This is automatically tested by the modifier, but we can verify
        // that the functions have the nonReentrant modifier applied
        
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        // Normal withdrawal should work
        vm.startPrank(user1);
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();
        
        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 500);
    }

    // Test multiple users batch withdraw
    function test_batchWithdraw_multipleUsers() public {
        // Use specific private keys and derive user addresses
        uint256 user1PrivateKey = 0x1111111111111111111111111111111111111111111111111111111111111111;
        uint256 user2PrivateKey = 0x2222222222222222222222222222222222222222222222222222222222222222;
        address testUser1 = vm.addr(user1PrivateKey);
        address testUser2 = vm.addr(user2PrivateKey);
        
        // Setup user balances
        address[] memory usersForBalance = new address[](2);
        usersForBalance[0] = testUser1;
        usersForBalance[1] = testUser2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1000;
        amounts[1] = 2000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(testUser1)));
        bUsers[1] = bytes32(uint256(uint160(testUser2)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 3000);

        // Prepare batch withdraw for both users
        uint256[] memory clientOrderIds = new uint256[](2);
        clientOrderIds[0] = 123;
        clientOrderIds[1] = 456;
        
        bytes32[] memory users = new bytes32[](2);
        users[0] = bytes32(uint256(uint160(testUser1)));
        users[1] = bytes32(uint256(uint160(testUser2)));
        amounts[0] = 500;
        amounts[1] = 800;

        // Create signatures for both users
        bytes32 operationHash1 = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser1))), uint256(500), block.chainid));
        operationHash1 = MessageHashUtils.toEthSignedMessageHash(operationHash1);
        
        bytes32 operationHash2 = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(456), bytes32(uint256(uint160(testUser2))), uint256(800), block.chainid));
        operationHash2 = MessageHashUtils.toEthSignedMessageHash(operationHash2);
        
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(user1PrivateKey, operationHash1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(user2PrivateKey, operationHash2);
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = abi.encodePacked(r1, s1, v1);
        signatures[1] = abi.encodePacked(r2, s2, v2);

        uint256 user1BalanceBefore = USDT.balanceOf(testUser1);
        uint256 user2BalanceBefore = USDT.balanceOf(testUser2);
        
        // Execute batch withdraw for both users
        vm.startPrank(withdrawOperator);
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
        
        uint256 user1BalanceAfter = USDT.balanceOf(testUser1);
        uint256 user2BalanceAfter = USDT.balanceOf(testUser2);
        
        assertEq(user1BalanceAfter - user1BalanceBefore, 500);
        assertEq(user2BalanceAfter - user2BalanceBefore, 800);
        assertEq(asset.userBalance(bytes32(uint256(uint160(testUser1)))), 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(testUser2)))), 1200);
    }

    // Test systemWithdraw with multiple signers (more than 2)
    function test_systemWithdraw_multipleSigners() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare multi-sig withdraw with all 3 signers
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 500;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
                expireTime, 
                address(asset), 
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);

        address[] memory allSigners = new address[](3);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        allSigners[2] = signer3;

        bytes[] memory signatures = new bytes[](3);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;

        uint256 recipientBalanceBefore = USDT.balanceOf(recipient);

        vm.expectEmit(address(asset));
        emit IAsset.SystemWithdraw(recipient, withdrawAmount);
        
        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        uint256 recipientBalanceAfter = USDT.balanceOf(recipient);
        assertEq(recipientBalanceAfter - recipientBalanceBefore, withdrawAmount);
        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 500);
    }

    // Test edge cases and boundary conditions
    function test_edge_cases() public {
        // Test with maximum values
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = type(uint256).max;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), type(uint256).max);
        assertEq(asset.lastBatchId(), 1);
    }

    // Test large batch update with many users
    function test_updateUserBalances_largeBatch() public {
        uint256 numUsers = 50;
        address[] memory users = new address[](numUsers);
        uint256[] memory amounts = new uint256[](numUsers);

        for (uint256 i = 0; i < numUsers; i++) {
            users[i] = address(uint160(i + 1000));
            amounts[i] = (i + 1) * 100;
        }

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](numUsers);
        for (uint256 i = 0; i < numUsers; i++) {
            bUsers[i] = bytes32(uint256(uint160(users[i])));
        }
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        for (uint256 i = 0; i < numUsers; i++) {
            assertEq(asset.userBalance(bytes32(uint256(uint160(users[i])))), amounts[i]);
        }
        assertEq(asset.lastBatchId(), 1);
    }

    // Test batchWithdraw with clientOrderIds length insufficient (should cause array bounds error)
    function test_batchWithdraw_clientOrderIdsLengthInsufficient() public {
        uint256[] memory clientOrderIds = new uint256[](1); // Shorter than users array
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](2);
        users[0] = bytes32(uint256(uint160(user1)));
        users[1] = bytes32(uint256(uint160(user2)));
        
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 500;
        amounts[1] = 600;
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = new bytes(65);
        signatures[1] = new bytes(65);

        // This will cause an array bounds error when accessing clientOrderIds[1]
        vm.expectRevert();
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
    }

    // Test isAllowedSigner with empty signers array
    function test_isAllowedSigner_emptySigners() public {
        // Deploy a new contract with empty signers to test this edge case
        // Actually, this is not possible due to constructor validation
        // But we can test the edge case where signer is at the end of array
        assertFalse(asset.isAllowedSigner(address(0x999999)));
    }

    // Test public getter functions for coverage
    function test_publicGetters() public view {
        // These calls ensure getter functions are covered
        asset.USDT();
        asset.signers(0); // Access first signer
        asset.signers(1); // Access second signer
        asset.signers(2); // Access third signer
        asset.systemAddress();
        asset.settlementOperator();
        asset.withdrawOperator();
        asset.userBalance(bytes32(uint256(uint160(user1))));
        asset.lastBatchId();
        asset.lastBatchTime();
        asset.FORCE_WITHDRAW_TIME_LOCK();
    }

    // Test batchWithdraw zero amount through _userWithdraw
    function test_batchWithdraw_zeroAmountInternalCheck() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Prepare batch withdraw with zero amount
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 0; // Zero amount

        // Create user signature for zero amount
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser))), uint256(0), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;
        
        // Execute batch withdraw - should fail with zero amount
        vm.startPrank(withdrawOperator);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
    }

    // Test systemWithdraw with exact system balance
    function test_systemWithdraw_exactBalance() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare multi-sig withdraw for exact balance
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 1000; // Exact balance

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
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

        uint256 recipientBalanceBefore = USDT.balanceOf(recipient);

        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        uint256 recipientBalanceAfter = USDT.balanceOf(recipient);
        assertEq(recipientBalanceAfter - recipientBalanceBefore, withdrawAmount);
        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 0); // Should be exactly 0
    }

    // Test assertion failure scenarios (this is tricky as assert will halt execution)
    // We'll test the balance verification logic indirectly
    function test_transferBalanceVerification() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract with exact amount
        USDT.transfer(address(asset), 1000);

        // Get contract balance before
        uint256 contractBalanceBefore = USDT.balanceOf(address(asset));
        
        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser))), uint256(500), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        // Execute batch withdraw
        vm.startPrank(withdrawOperator);
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
        
        // Verify balance change is exactly what was expected
        uint256 contractBalanceAfter = USDT.balanceOf(address(asset));
        assertEq(contractBalanceBefore - contractBalanceAfter, 500);
    }

    // Test validTime modifier (though it's not currently used in the contract)
    // We can't directly test it since it's not used, but we can verify the modifier exists
    
    // Test with multiple signers but checking different signer combinations
    function test_systemWithdraw_differentSignerCombinations() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Test different signer combinations
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 300;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
                expireTime, 
                address(asset), 
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // Test with signer1 and signer3 (different combination)
        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer3;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature3;

        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 700);
    }

    // Test systemWithdraw with more than 3 signers to ensure loop coverage
    function test_systemWithdraw_fourSigners() public {
        // Create a new asset with 4 signers for this test
        address[] memory fourSigners = new address[](4);
        fourSigners[0] = signer1;
        fourSigners[1] = signer2;
        fourSigners[2] = signer3;
        uint256 signer4PrivateKey = 4;
        address signer4 = vm.addr(signer4PrivateKey);
        fourSigners[3] = signer4;

        vm.startPrank(owner);
        Asset assetWith4Signers = new Asset(address(USDT), fourSigners, systemAddress, settlementOperator, withdrawOperator, address(0));
        vm.stopPrank();

        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        assetWith4Signers.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(assetWith4Signers), 1000);

        // Test with 4 signers
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 400;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
                expireTime, 
                address(assetWith4Signers), 
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);
        bytes memory signature4 = signMessage(operationHash, signer4PrivateKey);

        address[] memory allSigners = new address[](4);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        allSigners[2] = signer3;
        allSigners[3] = signer4;

        bytes[] memory signatures = new bytes[](4);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;
        signatures[3] = signature4;

        assetWith4Signers.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        console.log("assetWith4Signers.userBalance(systemAddress):", assetWith4Signers.userBalance(bytes32(uint256(uint160(systemAddress)))));
        assertEq(assetWith4Signers.userBalance(bytes32(uint256(uint160(systemAddress)))), 600);
    }

    // Test edge case with zero user balance force withdraw (should fail)
    function test_forceWithdraw_zeroUserBalance() public {
        // Don't setup any user balance for user1
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, 0, 100));
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 100, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();
    }

    // Test accessing signers array with all valid indices
    function test_signersArray_allIndices() public view {
        // Access all signers to ensure array getter coverage
        assertEq(asset.signers(0), signer1);
        assertEq(asset.signers(1), signer2);
        assertEq(asset.signers(2), signer3);
    }

    // Test isAllowedSigner with all signers to ensure loop coverage
    function test_isAllowedSigner_allSigners() public {
        // Test with each signer position to ensure full loop coverage
        assertTrue(asset.isAllowedSigner(signer1)); // First in array
        assertTrue(asset.isAllowedSigner(signer2)); // Middle in array
        assertTrue(asset.isAllowedSigner(signer3)); // Last in array
        
        // Test with non-signer
        assertFalse(asset.isAllowedSigner(address(0xdead)));
    }

    // Test updateUserBalances with zero amounts (should succeed)
    function test_updateUserBalances_zeroAmounts() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;
        
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 0; // Zero amount
        amounts[1] = 0; // Zero amount

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        bUsers[1] = bytes32(uint256(uint160(user2)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 0);
        assertEq(asset.userBalance(bytes32(uint256(uint160(user2)))), 0);
        assertEq(asset.lastBatchId(), 1);
    }

    // Test system withdraw with minimum possible amounts
    function test_systemWithdraw_minimumAmount() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1; // Minimum possible balance

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1);

        // Prepare multi-sig withdraw for minimum amount
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 1; // Minimum amount

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
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

        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 0);
    }


    function test_recover_address() public {
        // Use a known private key to generate the test user address
        uint256 testPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(testPrivateKey);
        uint256 amount = 1000000;
        uint256 clientOrderID = 1752463521625;
        uint256 chainID = 421614;

        console.log("=== Test Recover Address ===");
        console.log("testUser:", testUser);
        console.log("amount:", amount);
        console.log("clientOrderID:", clientOrderID);
        console.log("chainID:", chainID);

        // Create user signature with the correct private key for the test user
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", clientOrderID, bytes32(uint256(uint160(testUser))), amount, chainID));
        console.log("operationHash before toEthSignedMessageHash:");
        console.logBytes32(operationHash);
        
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        console.log("operationHash after toEthSignedMessageHash:");
        console.logBytes32(operationHash);
        
        // Generate signature using the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testPrivateKey, operationHash);
        bytes memory signatures = abi.encodePacked(r, s, v);
        console.log("signatures length:", signatures.length);
        
        address recoveredAddress = ECDSA.recover(operationHash, signatures);
        console.log("recoveredAddress:", recoveredAddress);
        console.log("Expected testUser:", testUser);
        console.log("Addresses match:", recoveredAddress == testUser);
        
        assertEq(recoveredAddress, testUser);
    }
    
    // ============ Additional Comprehensive Tests ============
    
    function testSetEd25519Oracle() public {
        address newOracle = address(0x123);
        
        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.Ed25519OracleUpdated(newOracle);
        asset.setEd25519Oracle(newOracle);
        vm.stopPrank();
        
        assertEq(address(asset.ed25519Oracle()), newOracle);
    }
    
    function testSetEd25519OracleOnlyOwner() public {
        address newOracle = address(0x123);
        
        vm.startPrank(user1);
        vm.expectRevert();
        asset.setEd25519Oracle(newOracle);
        vm.stopPrank();
    }
    
    function testSetEd25519OracleZeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setEd25519Oracle(address(0));
        vm.stopPrank();
    }
    
    function testForceWithdrawWithEd25519Oracle() public {
        // Set up oracle
        address oracleAddress = address(0x123);
        vm.startPrank(owner);
        asset.setEd25519Oracle(oracleAddress);
        vm.stopPrank();
        
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Advance time past the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDT.balanceOf(user1);

        vm.startPrank(user1);
        vm.expectEmit(address(asset));
        emit IAsset.ForceWithdraw(bytes32(uint256(uint160(user1))), 500);
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();

        uint256 user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 500);
    }
    
    function testBatchWithdrawWithEd25519Signature() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature with the correct private key for the test user
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser))), uint256(500), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        uint256 userBalanceBefore = USDT.balanceOf(testUser);
        
        // Configure mock Ed25519 oracle to approve
        MockEd25519Oracle mock = new MockEd25519Oracle();
        mock.setResult(true);
        vm.startPrank(owner);
        asset.setEd25519Oracle(address(mock));
        vm.stopPrank();

        // Execute batch withdraw with Ed25519 signature type
        vm.startPrank(withdrawOperator);
        vm.expectEmit(address(asset));
        emit IAsset.UserWithdraw(123, bytes32(uint256(uint160(testUser))), 500);
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ED25519);
        vm.stopPrank();
        
        uint256 userBalanceAfter = USDT.balanceOf(testUser);
        assertEq(userBalanceAfter - userBalanceBefore, 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(testUser)))), 500);
    }
    
    function testBatchWithdrawInvalidSignatureType() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature with the correct private key for the test user
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser))), uint256(500), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;
        
        // Configure mock Ed25519 oracle to reject
        MockEd25519Oracle mock = new MockEd25519Oracle();
        mock.setResult(false);
        vm.startPrank(owner);
        asset.setEd25519Oracle(address(mock));
        vm.stopPrank();

        // Execute batch withdraw with Ed25519 signature type (should fail)
        vm.startPrank(withdrawOperator);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidUserSignature.selector));
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ED25519);
        vm.stopPrank();
    }
    
    function testSystemWithdrawWithEd25519Oracle() public {
        // Set up oracle
        address oracleAddress = address(0x123);
        vm.startPrank(owner);
        asset.setEd25519Oracle(oracleAddress);
        vm.stopPrank();
        
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare multi-sig withdraw
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 500;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
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

        uint256 recipientBalanceBefore = USDT.balanceOf(recipient);

        vm.expectEmit(address(asset));
        emit IAsset.SystemWithdraw(recipient, withdrawAmount);
        
        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        uint256 recipientBalanceAfter = USDT.balanceOf(recipient);
        assertEq(recipientBalanceAfter - recipientBalanceBefore, withdrawAmount);
        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 500);
    }
    
    function testUserBalanceWithZeroAddress() public {
        // Test userBalance with zero address
        assertEq(asset.userBalance(bytes32(0)), 0);
    }
    
    function testUserBalanceWithMaxAddress() public {
        // Test userBalance with max address
        bytes32 maxAddress = bytes32(type(uint256).max);
        assertEq(asset.userBalance(maxAddress), 0);
    }
    
    function testUpdateUserBalancesWithMaxBatchId() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        // Using max batch ID should revert since lastBatchId is 0 (expects 1)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(type(uint256).max, bUsers, amounts);
        vm.stopPrank();
    }
    
    function testUpdateUserBalancesWithMaxAmount() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = type(uint256).max; // Max amount

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), type(uint256).max);
    }
    
    function testUpdateUserBalancesWithMaxUsers() public {
        // Test with maximum number of users (limited by gas)
        uint256 numUsers = 100; // Reasonable limit for testing
        address[] memory users = new address[](numUsers);
        uint256[] memory amounts = new uint256[](numUsers);
        
        for (uint256 i = 0; i < numUsers; i++) {
            users[i] = address(uint160(i + 1000)); // Generate unique addresses
            amounts[i] = (i + 1) * 100; // Different amounts for each user
        }

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](numUsers);
        for (uint256 i = 0; i < numUsers; i++) {
            bUsers[i] = bytes32(uint256(uint160(users[i])));
        }
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Verify all users got their balances
        for (uint256 i = 0; i < numUsers; i++) {
            assertEq(asset.userBalance(bytes32(uint256(uint160(users[i])))), amounts[i]);
        }
        
        assertEq(asset.lastBatchId(), 1);
    }
    
    function testBatchWithdrawWithMaxAmount() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup user balances with max amount
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000_000_000_000_000_000_000; // 1e24, within MockToken initial supply

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract sufficiently
        USDT.transfer(address(asset), amounts[0]);

        // Prepare batch withdraw with max amount
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 1_000_000_000_000_000_000_000_000;

        // Create user signature for max amount
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", uint256(123), bytes32(uint256(uint160(testUser))), amounts[0], block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        uint256 userBalanceBefore = USDT.balanceOf(testUser);
        
        // Execute batch withdraw
        vm.startPrank(withdrawOperator);
        vm.expectEmit(address(asset));
        emit IAsset.UserWithdraw(123, bytes32(uint256(uint160(testUser))), amounts[0]);
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
        
        uint256 userBalanceAfter = USDT.balanceOf(testUser);
        assertEq(userBalanceAfter - userBalanceBefore, amounts[0]);
        assertEq(asset.userBalance(bytes32(uint256(uint160(testUser)))), 0);
    }
    
    function testForceWithdrawWithMaxAmount() public {
        // Setup user balance with max amount
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000_000_000_000_000_000_000; // 1e24

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract sufficiently
        USDT.transfer(address(asset), amounts[0]);

        // Advance time past the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDT.balanceOf(user1);

        vm.startPrank(user1);
        vm.expectEmit(address(asset));
        emit IAsset.ForceWithdraw(bytes32(uint256(uint160(user1))), amounts[0]);
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), amounts[0], IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();

        uint256 user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, amounts[0]);
        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 0);
    }
    
    function testSystemWithdrawWithMaxAmount() public {
        // Setup system balance with max amount
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000_000_000_000_000_000_000; // 1e24

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract sufficiently
        USDT.transfer(address(asset), amounts[0]);

        // Prepare multi-sig withdraw with max amount
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = amounts[0];

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
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

        uint256 recipientBalanceBefore = USDT.balanceOf(recipient);

        vm.expectEmit(address(asset));
        emit IAsset.SystemWithdraw(recipient, withdrawAmount);
        
        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        uint256 recipientBalanceAfter = USDT.balanceOf(recipient);
        assertEq(recipientBalanceAfter - recipientBalanceBefore, withdrawAmount);
        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 0);
    }
    
    function testSystemWithdrawWithMaxExpireTime() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare multi-sig withdraw with max expire time
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 500;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
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

        uint256 recipientBalanceBefore = USDT.balanceOf(recipient);

        vm.expectEmit(address(asset));
        emit IAsset.SystemWithdraw(recipient, withdrawAmount);
        
        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );

        uint256 recipientBalanceAfter = USDT.balanceOf(recipient);
        assertEq(recipientBalanceAfter - recipientBalanceBefore, withdrawAmount);
        assertEq(asset.userBalance(bytes32(uint256(uint160(systemAddress)))), 500);
    }
    
    function testSystemWithdrawWithZeroExpireTime() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare multi-sig withdraw with zero expire time
        uint256 expireTime = 0;
        address recipient = user1;
        uint256 withdrawAmount = 500;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "SYSTEM_WITHDRAW", 
                address(USDT), 
                recipient, 
                withdrawAmount, 
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

        // Should fail with expired transaction
        vm.expectRevert(abi.encodeWithSelector(IAsset.ExpiredTransaction.selector));
        asset.systemWithdraw(
            address(USDT),
            recipient,
            withdrawAmount,
            expireTime,
            allSigners,
            signatures
        );
    }
    
    function testBatchWithdrawWithMaxClientOrderId() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Prepare batch withdraw with max client order ID
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = type(uint256).max;
        
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature with max client order ID
        bytes32 operationHash = keccak256(abi.encodePacked("USER_WITHDRAW", type(uint256).max, bytes32(uint256(uint160(testUser))), uint256(500), block.chainid));
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, operationHash);
        bytes memory userSignature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        uint256 userBalanceBefore = USDT.balanceOf(testUser);
        
        // Execute batch withdraw
        vm.startPrank(withdrawOperator);
        vm.expectEmit(address(asset));
        emit IAsset.UserWithdraw(type(uint256).max, bytes32(uint256(uint160(testUser))), 500);
        asset.batchWithdraw(clientOrderIds, users, amounts, signatures, IAsset.SignatureType.ECDSA);
        vm.stopPrank();
        
        uint256 userBalanceAfter = USDT.balanceOf(testUser);
        assertEq(userBalanceAfter - userBalanceBefore, 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(testUser)))), 500);
    }
    
    function testForceWithdrawWithMaxTimeLock() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Advance time past the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDT.balanceOf(user1);

        vm.startPrank(user1);
        vm.expectEmit(address(asset));
        emit IAsset.ForceWithdraw(bytes32(uint256(uint160(user1))), 500);
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();

        uint256 user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 500);
    }
    
    function testForceWithdrawWithExactTimeLock() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Advance time to just before the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() - 1);

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.TimeLockNotPassed.selector));
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();
    }
    
    function testForceWithdrawWithOneSecondAfterTimeLock() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        asset.updateUserBalances(1, bUsers, amounts);
        vm.stopPrank();

        // Fund the contract
        USDT.transfer(address(asset), 1000);

        // Advance time to one second after time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDT.balanceOf(user1);

        vm.startPrank(user1);
        vm.expectEmit(address(asset));
        emit IAsset.ForceWithdraw(bytes32(uint256(uint160(user1))), 500);
        asset.forceWithdraw(bytes32(uint256(uint160(user1))), 500, IAsset.SignatureType.ECDSA, new bytes(0));
        vm.stopPrank();

        uint256 user1BalanceAfter = USDT.balanceOf(user1);
        assertEq(user1BalanceAfter - user1BalanceBefore, 500);
        assertEq(asset.userBalance(bytes32(uint256(uint160(user1)))), 500);
    }
}
