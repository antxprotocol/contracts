// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

/**
 * @title SetBLSValidatorsScript
 * @notice Updates BLS settlement validators (pubkeys + min signatures) via setSettlementValidators().
 *
 * Required env vars (set in .env):
 *   CURRENT_ENV                        = testnet | mainnet
 *   PRIVATE_KEY                        = owner private key
 *   TESTNET_ASSET_PROXY_ADDRESS        = proxy address on testnet
 *   MAINNET_ASSET_PROXY_ADDRESS        = proxy address on mainnet
 *   TESTNET_BLS_PUBKEYS                = comma-separated 0x-prefixed 128-byte G1 pubkeys (testnet)
 *   MAINNET_BLS_PUBKEYS                = comma-separated 0x-prefixed 128-byte G1 pubkeys (mainnet)
 *   TESTNET_BLS_MIN_SIGNATURES         = minimum required signatures (testnet)
 *   MAINNET_BLS_MIN_SIGNATURES         = minimum required signatures (mainnet)
 *
 * Example .env entry:
 *   TESTNET_BLS_PUBKEYS=0xaabbcc...<128 bytes hex>,0xddeeff...<128 bytes hex>
 *   TESTNET_BLS_MIN_SIGNATURES=2
 */

import {Script} from "@forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Asset.sol";

contract SetBLSValidatorsScript is Script {
    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address proxyAddress;
        string[] memory pkHexList;
        uint256 minSignatures;

        if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            proxyAddress    = vm.envAddress("TESTNET_ASSET_PROXY_ADDRESS");
            pkHexList       = vm.envString("TESTNET_BLS_PUBKEYS", ",");
            minSignatures   = vm.envUint("TESTNET_BLS_MIN_SIGNATURES");
        } else {
            proxyAddress    = vm.envAddress("MAINNET_ASSET_PROXY_ADDRESS");
            pkHexList       = vm.envString("MAINNET_BLS_PUBKEYS", ",");
            minSignatures   = vm.envUint("MAINNET_BLS_MIN_SIGNATURES");
        }

        console.log("Asset proxy address:", proxyAddress);
        console.log("Validator count:", pkHexList.length);
        console.log("Min signatures:", minSignatures);

        bytes[] memory pks = new bytes[](pkHexList.length);
        for (uint256 i = 0; i < pkHexList.length; i++) {
            pks[i] = vm.parseBytes(pkHexList[i]);
            console.log("  pk[%d] length: %d bytes", i, pks[i].length);
        }

        Asset asset = Asset(payable(proxyAddress));
        asset.setSettlementValidators(pks, minSignatures);

        uint256 active = asset.settlementActiveValidators();
        uint256 minSig = asset.settlementMinSignatures();
        console.log("Done. Active validators:", active);
        console.log("Done. Min signatures:", minSig);

        vm.stopBroadcast();
    }
}

/**
 * @title SetBLSMinSignaturesScript
 * @notice Updates only the minimum required BLS signatures via setSettlementMinSignatures().
 *
 * Required env vars (set in .env):
 *   CURRENT_ENV                        = testnet | mainnet
 *   PRIVATE_KEY                        = owner private key
 *   TESTNET_ASSET_PROXY_ADDRESS        = proxy address on testnet
 *   MAINNET_ASSET_PROXY_ADDRESS        = proxy address on mainnet
 *   TESTNET_BLS_MIN_SIGNATURES         = new minimum required signatures (testnet)
 *   MAINNET_BLS_MIN_SIGNATURES         = new minimum required signatures (mainnet)
 */
contract SetBLSMinSignaturesScript is Script {
    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        string memory currentEnv = vm.envString("CURRENT_ENV");
        address proxyAddress;
        uint256 minSignatures;

        if (keccak256(bytes(currentEnv)) == keccak256(bytes("testnet"))) {
            proxyAddress  = vm.envAddress("TESTNET_ASSET_PROXY_ADDRESS");
            minSignatures = vm.envUint("TESTNET_BLS_MIN_SIGNATURES");
        } else {
            proxyAddress  = vm.envAddress("MAINNET_ASSET_PROXY_ADDRESS");
            minSignatures = vm.envUint("MAINNET_BLS_MIN_SIGNATURES");
        }

        console.log("Asset proxy address:", proxyAddress);
        console.log("New min signatures:", minSignatures);

        Asset asset = Asset(payable(proxyAddress));
        asset.setSettlementMinSignatures(minSignatures);

        console.log("Done. Min signatures:", asset.settlementMinSignatures());

        vm.stopBroadcast();
    }
}
