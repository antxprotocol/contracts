// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {BLS12381} from "../src/bls/BLS12381.sol";

/// @notice E2E test: whether Go-generated aggregate BLS signature passes contract verification.
/// @dev Must run on BSC node (fork) because it depends on BSC BLS precompile.
contract BLSE2ET is Test {
    BLS12381 bls;

    bytes constant G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    bytes constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    bytes constant PK0 =
        hex"000000000000000000000000000000000a1a1c26055a329817a5759d877a2795f9499b97d6056edde0eea39512f24e8bc874b4471f0501127abb1ea0d9f68ac10000000000000000000000000000000011392125a1c3750363c2c97d9650fb78696e6428db8ff9efaf0471cbfd20324916ab545746db83756d335e92f9e8c8b8";
    bytes constant PK1 =
        hex"000000000000000000000000000000000004066a1a5cb9cdf244e45f0a59cf579a78d90ac0bc24663565264601c1c9251c0aa3dfb9835b520e0ba0f211a6696c000000000000000000000000000000000250fee58f12e98c72bd7de41a2c57df2c35452a4abfb0cc2691eb363f7bb9897c38f8f94ab4f8d63673b61128f11b9e";
    bytes constant PK2 =
        hex"000000000000000000000000000000000355519968b7db86b1ceb2261e179f6cde1a6010b8588e4a1a59eae804c9eed5f3e3d433a69dabb1eb7403c9c2721116000000000000000000000000000000000e3e5890e55ee5cd46fbe01d22cfde2f1570f1e6a06c5719fab0bf77ac63f787ff34cecff52085d6369db4eeaed764a3";

    bytes constant AGG_SIG =
        hex"0000000000000000000000000000000000fc23c7acad1d99b8052b126ef130478daa861211494678cb7bc835341acfae24eabe52da926928a1d2bfd9205413f5000000000000000000000000000000000e792baa17ace4928957a8261cdfd5ab8c9a4bb9858c8da73ec46e7ce1ea28b54697d828628dba145150331fa5d142dd0000000000000000000000000000000018f80c68e0a9999799aa0ddb32d17276d54f2e6d68ec072beab990409e9c2bea0024d7cb39dcd2004fbc2bc580bb69290000000000000000000000000000000009e480bcb5618facfb76abd0f55e6eb15d2069c071959e5105b91f54204ba15a450cc3f5e298760814143119d0d35be9";

    bytes constant AGG_PK =
        hex"000000000000000000000000000000000355519968b7db86b1ceb2261e179f6cde1a6010b8588e4a1a59eae804c9eed5f3e3d433a69dabb1eb7403c9c2721116000000000000000000000000000000000e3e5890e55ee5cd46fbe01d22cfde2f1570f1e6a06c5719fab0bf77ac63f787ff34cecff52085d6369db4eeaed764a3";

    bytes32 constant MSG_HASH =
        0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789;

    bytes constant BITMASK = hex"03";

    function setUp() public {
        bls = new BLS12381(DST, G1_GENERATOR);
    }

    /// @notice Verify that Go-generated aggregate signature passes contract verification
    function testBLSVerifyAggregate() public view {
        bytes memory hashedMsg = bls.hashToPoint(MSG_HASH);

        bool ok = bls.verifyAggregate(AGG_SIG, hashedMsg, AGG_PK);
        assertTrue(
            ok,
            "BLS verifyAggregate failed: Go-generated signature is incompatible with contract"
        );
    }

    /// @notice Verify aggregatePubkeys matches Go-side aggregate result
    function testAggregatePubkeys() public view {
        bytes[] memory signingPks = new bytes[](2);
        signingPks[0] = PK0;
        signingPks[1] = PK1;

        bytes memory contractAgg = bls.aggregatePubkeys(signingPks);
        assertEq(
            keccak256(contractAgg),
            keccak256(AGG_PK),
            "aggregatePubkeys mismatch: Go aggPk != contract aggPk"
        );
    }
}

