// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Asset} from "../src/Asset.sol";
import {IAsset} from "../src/interfaces/IAsset.sol";
import {SettlementForTest} from "../src/SettlementForTest.sol";
import {MockToken} from "../src/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract AssetTest is Test {
    Asset public asset;
    SettlementForTest public settlement;

    // mock token
    MockToken internal USDT = new MockToken("USDT", "USDT");

    // initial addresses
    address internal signer1 = address(0x1);
    address internal signer2 = address(0x2);
    address internal signer3 = address(0x3);
    address internal owner = address(0x4);
    address internal user1 = address(0x5);
    address[] internal signers = [signer1, signer2, signer3];
    address[] internal batchSubmitter = signers;

    // MockToken that can fail transfers for testing
    MockToken internal failingUSDT;

    function setUp() public {
        vm.startPrank(owner);
        asset = new Asset(address(USDT), signers);
        settlement = new SettlementForTest(address(asset), batchSubmitter);
        
        // Create a failing USDT mock for testing transfer failures
        failingUSDT = new MockToken("fUSDT", "fUSDT");
        failingUSDT.setFailTransfers(true);
        vm.stopPrank();
    }

    function test_initial() public {
        assertEq(asset.getTotalBalance(), 0);
        assertEq(asset.owner(), owner);
        assertEq(asset.getUSDT(), address(USDT));
        assertEq(asset.getSigners(), signers);
        assertEq(asset.getFeeBalance(), 0);
        assertEq(asset.getUserBalance(signer1), 0);

        USDT.transfer(address(asset), 1000);
        assertEq(asset.getTotalBalance(), 1000);
    }

    function test_setSettlementContract() public {
        // not equal
        assertNotEq(asset.getSettlementContract(), address(settlement));

        // invalid owner
        vm.startPrank(signer1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, signer1));
        asset.setSettlementContract(address(settlement));
        // equal
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        vm.stopPrank();
        assertEq(asset.getSettlementContract(), address(settlement));
    }

    function test_USDTBalance() public {
        // initial balance
        assertEq(USDT.balanceOf(address(asset)), 0);
        assertEq(asset.getFeeBalance(), 0);
        assertEq(asset.getTotalBalance(), 0);

        // deposit
        USDT.transfer(address(asset), 1000);
        assertEq(asset.getFeeBalance(), 0);
        assertEq(asset.getTotalBalance(), 1000);
    }

    function test_userBalance() public {
        assertEq(asset.getUserBalance(signer1), 0);

        vm.startPrank(owner);

        // expect revert
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        settlement.addUserBalanceForTest(signer1, 1000);

        // set settlement contract
        asset.setSettlementContract(address(settlement));

        // add balance again
        settlement.addUserBalanceForTest(signer1, 1000);
        assertEq(asset.getUserBalance(signer1), 1000);

        // add balance again
        settlement.addUserBalanceForTest(signer1, 1000);
        assertEq(asset.getUserBalance(signer1), 2000);

        // sub balance
        settlement.subUserBalanceForTest(signer1, 1000);
        assertEq(asset.getUserBalance(signer1), 1000);

        vm.stopPrank();
    }

    function test_feeBalance() public {
        assertEq(asset.getFeeBalance(), 0);

        vm.startPrank(owner);

        // expect revert
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        settlement.addFeeBalanceForTest(1000);

        // set settlement contract
        asset.setSettlementContract(address(settlement));

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.getFeeBalance(), 1000);

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.getFeeBalance(), 2000);
        vm.stopPrank();
    }

    function test_feeWithdraw() public {
        assertEq(asset.getFeeBalance(), 0);

        vm.startPrank(owner);

        // expect revert
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        settlement.addFeeBalanceForTest(1000);

        // set settlement contract
        asset.setSettlementContract(address(settlement));

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.getFeeBalance(), 1000);

        // add balance again
        settlement.addFeeBalanceForTest(1000);
        assertEq(asset.getFeeBalance(), 2000);

        // try withdraw
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, address(asset), USDT.balanceOf(address(asset)), 500
            )
        );
        asset.withdrawFee(signer2, 500);

        // mint USDT to asset
        console.log("owner USDT balance", USDT.balanceOf(address(asset)));
        USDT.mint(address(asset), 2000);
        assertEq(asset.getTotalBalance(), 2000);

        // withdraw fee - transfer first then emit event
        vm.expectEmit(address(USDT));
        emit IERC20.Transfer(address(asset), signer2, 500);

        vm.expectEmit(address(asset));
        emit IAsset.WithdrawFee(signer2, 500);
        asset.withdrawFee(signer2, 500);

        assertEq(asset.getFeeBalance(), 1500);
        assertEq(USDT.balanceOf(signer2), 500);

        vm.stopPrank();
    }

    function test_withdraw() public {
        assertEq(asset.getUserBalance(signer1), 0);

        vm.startPrank(owner);
        // set settlement contract
        asset.setSettlementContract(address(settlement));

        // mint USDT to asset
        console.log("owner USDT balance", USDT.balanceOf(address(asset)));
        USDT.mint(address(asset), 2000);
        assertEq(asset.getTotalBalance(), 2000);

        // add user balance
        settlement.addUserBalanceForTest(user1, 1000);
        assertEq(asset.getUserBalance(user1), 1000);
        vm.stopPrank();

        // change to user1
        vm.startPrank(user1);

        // expect revert with custom error
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, user1, 1000, 1001));
        asset.withdraw(1001);

        // expect event - transfer first then emit event
        vm.expectEmit(address(USDT));
        emit IERC20.Transfer(address(asset), user1, 1000);

        vm.expectEmit(address(asset));
        emit IAsset.Withdraw(user1, 1000);
        asset.withdraw(1000);

        // check user balance
        assertEq(asset.getUserBalance(user1), 0);

        // check total balance
        assertEq(asset.getTotalBalance(), 1000);

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
        invalidSigners[2] = signer3;
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
        
        // Try to add user balance with zero amount
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        settlement.addUserBalanceForTest(user1, 0);
        
        // Try to subtract user balance with zero amount
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        settlement.subUserBalanceForTest(user1, 0);
        
        // Try to add fee balance with zero amount
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        settlement.addFeeBalanceForTest(0);
        vm.stopPrank();
        
        // Try to withdraw user balance with zero amount
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.withdraw(0);
        vm.stopPrank();
        
        // Try to withdraw fee balance with zero amount
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.withdrawFee(signer2, 0);
        vm.stopPrank();
    }

    // Test the validAddress modifier in withdrawFee
    function test_withdrawFee_zeroAddress() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        settlement.addFeeBalanceForTest(1000);
        USDT.mint(address(asset), 1000);
        
        // Try to withdraw fee to zero address
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.withdrawFee(address(0), 500);
        vm.stopPrank();
    }

    // Test the validAddress modifier when adding user balance
    function test_addUserBalance_zeroAddress() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Try to add balance to zero address
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        settlement.addUserBalanceForTest(address(0), 1000);
        vm.stopPrank();
    }

    // Test the validAddress modifier when subtracting from user balance
    function test_subUserBalance_zeroAddress() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Try to subtract balance from zero address
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        settlement.subUserBalanceForTest(address(0), 1000);
        vm.stopPrank();
    }

    // Test transfer failure scenario
    function test_withdraw_transferFailed() public {
        // Create a new asset contract using the failing transfer token
        vm.startPrank(owner);
        Asset failingAsset = new Asset(address(failingUSDT), signers);
        
        // Set settlement contract
        SettlementForTest newSettlement = new SettlementForTest(address(failingAsset), batchSubmitter);
        failingAsset.setSettlementContract(address(newSettlement));
        
        // Add user balance and mock tokens
        newSettlement.addUserBalanceForTest(user1, 1000);
        failingUSDT.mint(address(failingAsset), 2000);
        vm.stopPrank();
        
        // User tries to withdraw balance, but transfer will fail
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.TransferFailed.selector));
        failingAsset.withdraw(1000);
        vm.stopPrank();
    }

    // Test fee withdrawal transfer failure scenario
    function test_withdrawFee_transferFailed() public {
        // Create a new asset contract using the failing transfer token
        vm.startPrank(owner);
        Asset failingAsset = new Asset(address(failingUSDT), signers);
        
        // Set settlement contract
        SettlementForTest newSettlement = new SettlementForTest(address(failingAsset), batchSubmitter);
        failingAsset.setSettlementContract(address(newSettlement));
        
        // Add fee balance and mock tokens
        newSettlement.addFeeBalanceForTest(1000);
        failingUSDT.mint(address(failingAsset), 2000);
        
        // Try to withdraw fee, but transfer will fail
        vm.expectRevert(abi.encodeWithSelector(IAsset.TransferFailed.selector));
        failingAsset.withdrawFee(signer2, 500);
        vm.stopPrank();
    }

    // Test insufficient balance error when subtracting from user balance
    function test_subUserBalance_insufficientBalance() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Add balance
        settlement.addUserBalanceForTest(user1, 500);
        
        // Try to subtract an amount greater than the balance
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, user1, 500, 1000));
        settlement.subUserBalanceForTest(user1, 1000);
        vm.stopPrank();
    }

    // Test insufficient balance error when withdrawing fee
    function test_withdrawFee_insufficientBalance() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Add fee balance
        settlement.addFeeBalanceForTest(500);
        USDT.mint(address(asset), 1000);
        
        // Try to withdraw fee greater than the balance
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientFeeBalance.selector, 500, 1000));
        asset.withdrawFee(signer2, 1000);
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

    // Test getLastBatchTime and setLastBatchTime functions
    function test_lastBatchTime() public {
        // Initial value should be 0
        assertEq(asset.getLastBatchTime(), 0);
        
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Set a valid time
        uint256 newTime = block.timestamp;
        settlement.setLastBatchTimeForTest(newTime);
        
        // Check if time was updated
        assertEq(asset.getLastBatchTime(), newTime);
        
        // Set another time and verify update
        uint256 newerTime = block.timestamp + 100;
        
        // Check for LastBatchTimeUpdated event
        vm.expectEmit(address(asset));
        emit IAsset.LastBatchTimeUpdated(newerTime);
        
        settlement.setLastBatchTimeForTest(newerTime);
        assertEq(asset.getLastBatchTime(), newerTime);
        vm.stopPrank();
        
        // Try to call setLastBatchTime from non-settlement address
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.NotSettlementContract.selector));
        asset.setLastBatchTime(block.timestamp);
        vm.stopPrank();
    }

    // Test forceWithdraw function
    function test_forceWithdraw() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        
        // Set up last batch time
        uint256 currentTime = block.timestamp;
        settlement.setLastBatchTimeForTest(currentTime);
        
        // Add balance and tokens
        settlement.addUserBalanceForTest(user1, 1000);
        USDT.mint(address(asset), 2000);
        vm.stopPrank();
        
        // User tries to force withdraw before time lock period
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.TimeLockNotPassed.selector));
        asset.forceWithdraw(500);
        
        // Fast forward time beyond the time lock
        vm.warp(currentTime + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);
        
        // Now force withdraw should succeed
        // Expect USDT transfer event first
        vm.expectEmit(address(USDT));
        emit IERC20.Transfer(address(asset), user1, 500);
        
        // Then expect Withdraw event followed by ForceWithdraw event
        vm.expectEmit(address(asset));
        emit IAsset.Withdraw(user1, 500);
        
        vm.expectEmit(address(asset));
        emit IAsset.ForceWithdraw(user1, 500);
        
        asset.forceWithdraw(500);
        
        // Verify balance is updated
        assertEq(asset.getUserBalance(user1), 500);
        assertEq(USDT.balanceOf(user1), 500);
        vm.stopPrank();
        
        // Test force withdraw with too much amount
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, user1, 500, 600));
        asset.forceWithdraw(600);
        vm.stopPrank();
    }

    // Test zero amount validation in forceWithdraw
    function test_forceWithdraw_zeroAmount() public {
        vm.startPrank(owner);
        asset.setSettlementContract(address(settlement));
        uint256 currentTime = block.timestamp;
        settlement.setLastBatchTimeForTest(currentTime);
        
        // Fast forward time beyond the time lock
        vm.warp(currentTime + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);
        vm.stopPrank();
        
        // Try to force withdraw zero amount
        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.forceWithdraw(0);
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
