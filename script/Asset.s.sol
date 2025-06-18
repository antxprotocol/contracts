// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";
import "../src/Settlement.sol";
import {MockToken} from "../src/mock/MockToken.sol";

contract AssetScript is Script {
    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        address mockToken = 0x3253a335E7bFfB4790Aa4C25C4250d206E9b9773;
        console.log("USDC address at:", address(mockToken));

        // deploy mock token
        // MockToken mockToken = new MockToken("MockToken", "MT");
        // console.log("MockToken deployed at:", address(mockToken));

        address[] memory signers = new address[](3);
        signers[0] = 0x4626eb76a7c2896645B0117614Ec0555e6E3a180;
        signers[1] = 0x6c7459c4B3B84E24734E59D4a6749EB02Ea26406;
        signers[2] = 0x3171E2318402Cea35849CDaed28261A25e25849c;

        // Deploy asset
        Asset asset =  new Asset(
            address(mockToken),
            signers
        );
        console.log("Asset deployed at:", address(asset));


        address[] memory operators = new address[](1);
        operators[0] = vm.addr(privateKey);
        
        // deploy settlement
        Settlement settlement = new Settlement(
            address(asset),
            operators
        );
        console.log("Settlement deployed at:", address(settlement));


        // set settlement contract
        asset.setSettlementContract(address(settlement));
        console.log("Settlement contract set", asset.settlementContract());

        vm.stopBroadcast();
    }
}