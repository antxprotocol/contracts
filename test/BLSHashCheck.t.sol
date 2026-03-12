// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {BLS12381} from "../src/bls/BLS12381.sol";

/// @notice Verify kilic/bls12-381 HashToCurve output matches BLS12381.sol hashToPoint.
/// @dev Must run on BSC node (local or fork) because it depends on BSC precompile.
contract BLSHashCheckTest is Test {
    BLS12381 bls;

    bytes constant G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    bytes constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    bytes constant EXPECTED_HASH_POINT =
        hex"000000000000000000000000000000000c82527cab8fa318e4545b9b215e41c47ebac306c759c9af1464c857bcc5c4d0b5f5a65f1b9a6552b1aba9549b9ba012000000000000000000000000000000000a1a267dce1762767f1e0ec0e57f53ad20bb7f390962a6c21d0653ae197e17a12e7ab8190f482e0180103978dfdf793a0000000000000000000000000000000019e05466bd8d574af9a62c3a16b64e29de69a32895885ce5effb054dc2e999032fba3ded4ddcb5a0c37e931347c7e52a0000000000000000000000000000000005b6ca54fda207a7ec979220355a569758b486c1f21d174e0a6570765d3fcfca46a00300071567fbb0492012f91209b6";

    function setUp() public {
        bls = new BLS12381(DST, G1_GENERATOR);
    }

    function testHashToCurveCompatibility() public view {
        bytes32 msgHash =
            0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;

        bytes memory contractResult = bls.hashToPoint(msgHash);

        assertEq(contractResult.length, 256, "hashToPoint should return 256 bytes");
        assertEq(
            keccak256(contractResult),
            keccak256(EXPECTED_HASH_POINT),
            "kilic HashToCurve != BSC precompile hashToPoint"
        );
    }
}

