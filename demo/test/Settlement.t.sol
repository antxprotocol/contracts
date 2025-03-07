// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ISettlement} from "../src/interfaces/ISettlement.sol";
import {Settlement} from "../src/Settlement.sol";
import {Asset} from "../src/Asset.sol";

import {MockToken} from "../src/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";


contract SettlementTest is Test {
    Asset public asset;
    Settlement public settlement;

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
        settlement = new Settlement(address(asset), batchSubmitter);
        vm.stopPrank();
    }

    
}
