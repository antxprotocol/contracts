// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Asset} from "../src/Asset.sol";
import {IAsset} from "../src/interfaces/IAsset.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockToken} from "../src/mock/MockToken.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract AssetEdgeCasesTest is Test {
    Asset public asset;
    MockToken public USDT;
    address public owner;
    address public user1;
    address public user2;
    address public operator1;
    address public operator2;
    address public settlement;
    address public signer1;
    address public signer2;
    address public signer3;
    uint256 public signer1PrivateKey;
    uint256 public signer2PrivateKey;
    uint256 public signer3PrivateKey;

    function setUp() public {
        // Create mock USDT token
        USDT = new MockToken("USDT", "USDT");
        
        // Setup accounts
        owner = address(0x1);
        user1 = address(0x2);
        user2 = address(0x3);
        operator1 = address(0x4);
        operator2 = address(0x5);
        settlement = address(0x6);
        
        // Generate signers with private keys for testing
        signer1PrivateKey = 0x01;
        signer2PrivateKey = 0x02;
        signer3PrivateKey = 0x03;
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        signer3 = vm.addr(signer3PrivateKey);
        
        // Create signers array for Asset contract
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;
        
        // Deploy Asset contract with owner
        vm.startPrank(owner);
        asset = new Asset(address(USDT), signers);
        asset.setSettlementContract(settlement);
        
        // Give initial USDT to various accounts for testing
        USDT.mint(owner, 10000);
        USDT.mint(user1, 5000);
        USDT.mint(address(asset), 50000);
        USDT.transfer(address(asset), 1000);
        vm.stopPrank();
        
        // Set up initial state for asset contract
        vm.startPrank(settlement);
        asset.addUserBalance(user1, 2000);
        asset.addFeeBalance(5000);
        asset.addRiskMarginBalance(2000);
        asset.setLastBatchTime(block.timestamp);
        vm.stopPrank();
    }
    
    function signMessage(bytes32 messageHash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }
    
    function test_withdrawFee_time_expired() public {
        // Create a withdrawal request with an expired time
        uint256 expiredTime = block.timestamp - 1; // Expired (in the past)
        
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                address(USDT),
                user1,
                uint256(1000),
                expiredTime,
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
        
        // Should revert due to expired time
        vm.expectRevert("expired transaction");
        asset.withdrawFee(
            address(USDT),
            user1,
            1000,
            expiredTime,
            allSigners,
            signatures
        );
    }
    
    function test_withdrawFee_invalid_token() public {
        // Create a withdrawal request with a token that isn't USDT
        address invalidToken = address(0x9999);
        uint256 expireTime = block.timestamp + 1 hours;
        
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "WITHDDRAW_FEE",
                invalidToken,
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
        
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;
        
        // Should revert due to invalid token
        vm.expectRevert("invalid token");
        asset.withdrawFee(
            invalidToken,
            user1,
            1000,
            expireTime,
            allSigners,
            signatures
        );
    }
    
    function test_withdrawFee_invalid_allSigners_length() public {
        // Create a withdrawal request with only one signer (minimum is 2)
        uint256 expireTime = block.timestamp + 1 hours;
        
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
        
        address[] memory allSigners = new address[](1);
        allSigners[0] = signer1;
        
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature1;
        
        // Should revert due to invalid allSigners length
        vm.expectRevert("invalid allSigners length");
        asset.withdrawFee(
            address(USDT),
            user1,
            1000,
            expireTime,
            allSigners,
            signatures
        );
    }
    
    function test_withdrawFee_mismatched_signatures_length() public {
        // Create a withdrawal request with mismatched signers and signatures arrays
        uint256 expireTime = block.timestamp + 1 hours;
        
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
        
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        
        bytes[] memory signatures = new bytes[](1); // Only 1 signature for 2 signers
        signatures[0] = signature1;
        
        // Should revert due to mismatched lengths
        vm.expectRevert("invalid signatures length");
        asset.withdrawFee(
            address(USDT),
            user1,
            1000,
            expireTime,
            allSigners,
            signatures
        );
    }
    
    function test_withdrawFee_same_signer() public {
        // Create a withdrawal request with the same signer twice
        uint256 expireTime = block.timestamp + 1 hours;
        
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
        
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer1; // Same signer twice
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature1;
        
        // Should revert because signers must be different
        vm.expectRevert("can not be same signer");
        asset.withdrawFee(
            address(USDT),
            user1,
            1000,
            expireTime,
            allSigners,
            signatures
        );
    }
    
    function test_withdrawFee_invalid_signer() public {
        // Create a withdrawal request with a mismatched signer and signature
        uint256 expireTime = block.timestamp + 1 hours;
        
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
        bytes memory signature2 = signMessage(operationHash, signer1PrivateKey); // Wrong private key for signer2
        
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;
        
        // Should revert due to invalid signer
        vm.expectRevert("invalid signer");
        asset.withdrawFee(
            address(USDT),
            user1,
            1000,
            expireTime,
            allSigners,
            signatures
        );
    }
    
    function test_withdrawFee_not_allowed_signer() public {
        // Create a withdrawal request using a signer that's not in the allowed list
        uint256 expireTime = block.timestamp + 1 hours;
        
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
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey); // Not in allowed list
        
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer3; // Not in allowed list
        
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature3;
        
        // Verify signature recovery works correctly
        address recoveredSigner = vm.addr(signer3PrivateKey);
        assertEq(recoveredSigner, signer3);
        
        // Should revert because signer3 is not allowed
        vm.expectRevert("not allowed signer");
        asset.withdrawFee(
            address(USDT),
            user1,
            1000,
            expireTime,
            allSigners,
            signatures
        );
    }
} 