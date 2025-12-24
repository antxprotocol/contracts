// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockToken} from "../src/mock/MockToken.sol";

contract MockTokenTest is Test {
    MockToken public token;
    address public owner;
    address public user1;
    address public user2;

    function setUp() public {
        owner = address(0x1);
        user1 = address(0x2);
        user2 = address(0x3);

        vm.startPrank(owner);
        token = new MockToken("TestToken", "TTK");
        vm.stopPrank();
    }

    function test_initialState() public {
        assertEq(token.name(), "TestToken");
        assertEq(token.symbol(), "TTK");
        assertEq(token.shouldFailTransfers(), false);
        assertEq(token.balanceOf(owner), 1000000000000000000000000);
    }

    function test_mint() public {
        vm.startPrank(owner);
        token.mint(user1, 1000);
        vm.stopPrank();

        assertEq(token.balanceOf(user1), 1000);
    }

    function test_transfer_success() public {
        vm.startPrank(owner);
        token.transfer(user1, 1000);
        vm.stopPrank();

        assertEq(token.balanceOf(owner), 1000000000000000000000000 - 1000);
        assertEq(token.balanceOf(user1), 1000);
    }

    function test_transfer_fail() public {
        vm.startPrank(owner);
        // Set transfers to fail
        token.setFailTransfers(true);

        // Transfer should return false but not revert
        bool success = token.transfer(user1, 1000);
        assertFalse(success);

        // Balance should not change
        assertEq(token.balanceOf(owner), 1000000000000000000000000);
        assertEq(token.balanceOf(user1), 0);
        vm.stopPrank();
    }

    function test_transferFrom_success() public {
        vm.startPrank(owner);
        // Transfer some tokens to user1
        token.transfer(user1, 1000);
        vm.stopPrank();

        // User1 approves user2 to spend tokens
        vm.startPrank(user1);
        token.approve(user2, 500);
        vm.stopPrank();

        // User2 transfers tokens from user1 to themselves
        vm.startPrank(user2);
        bool success = token.transferFrom(user1, user2, 500);

        assertTrue(success);
        assertEq(token.balanceOf(user1), 500);
        assertEq(token.balanceOf(user2), 500);
        vm.stopPrank();
    }

    function test_transferFrom_fail() public {
        vm.startPrank(owner);
        // Transfer some tokens to user1
        token.transfer(user1, 1000);
        // Set transfers to fail
        token.setFailTransfers(true);
        vm.stopPrank();

        // User1 approves user2 to spend tokens
        vm.startPrank(user1);
        token.approve(user2, 500);
        vm.stopPrank();

        // User2 tries to transfer tokens from user1 to themselves
        vm.startPrank(user2);
        bool success = token.transferFrom(user1, user2, 500);

        assertFalse(success);
        assertEq(token.balanceOf(user1), 1000);
        assertEq(token.balanceOf(user2), 0);
        vm.stopPrank();
    }

    function test_setFailTransfers() public {
        // Initially should be false
        assertFalse(token.shouldFailTransfers());

        // Set to true
        vm.startPrank(owner);
        token.setFailTransfers(true);
        vm.stopPrank();

        assertTrue(token.shouldFailTransfers());

        // Set back to false
        vm.startPrank(owner);
        token.setFailTransfers(false);
        vm.stopPrank();

        assertFalse(token.shouldFailTransfers());
    }
}
