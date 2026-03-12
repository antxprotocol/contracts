// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/bls/BLS12381.sol";

/// @dev Mock BLS for tests: always accepts any signature (no real crypto).
contract MockBLS is IBLS {
    function hashToPoint(bytes32) external pure override returns (bytes memory) {
        return new bytes(256);
    }

    function aggregatePubkeys(bytes[] calldata) external pure override returns (bytes memory) {
        return new bytes(128);
    }

    function verifyAggregate(
        bytes calldata,
        bytes calldata,
        bytes calldata
    ) external pure override returns (bool) {
        return true;
    }
}
