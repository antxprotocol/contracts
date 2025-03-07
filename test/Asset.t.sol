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

    function setUp() public {
        vm.startPrank(owner);
        asset = new Asset(address(USDT), signers);
        settlement = new SettlementForTest(address(asset), batchSubmitter);
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
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                signer1
            )
        );
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
        vm.expectRevert("Not settlement contract");
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
        // TODO: use multi sig  test
 
        assertEq(asset.getFeeBalance(), 0);

        vm.startPrank(owner);

        // expect revert
        vm.expectRevert("Not settlement contract");
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
        // TODO: use multi sig  test
 
        assertEq(asset.getFeeBalance(), 0);

        vm.startPrank(owner);

        // expect revert
        vm.expectRevert("Not settlement contract");
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
                IERC20Errors.ERC20InsufficientBalance.selector,
                address(asset),
                USDT.balanceOf(address(asset)),
                500
            )
        );
        asset.withdrawFee(signer2, 500);

        // mint USDT to asset
        console.log("owner USDT balance", USDT.balanceOf(address(asset)));
        USDT.mint(address(asset), 2000);
        assertEq(asset.getTotalBalance(), 2000);

        // withdraw fee
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


        // change to user1
        vm.startPrank(user1);

        // expect revert
        vm.expectRevert("Insufficient user balance");
        asset.withdraw(1001);

        // expect event
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
}
