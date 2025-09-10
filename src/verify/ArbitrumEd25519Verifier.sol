// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

contract ArbitrumEd25519Verifier {
    // Ed25519 precompile contract address on Arbitrum
    address constant ED25519_PRECOMPILE = 0x0000000000000000000000000000000000000069;

    /**
     * @dev Verify Ed25519 signature
     * @param publicKey 32-byte Ed25519 public key
     * @param message Original message (arbitrary length)
     * @param signature 64-byte signature (R||S)
     */
    function verifyEd25519(
        bytes32 publicKey,
        bytes memory message,
        bytes calldata signature
    ) public view returns (bool) {
        require(signature.length == 64, "Signature must be 64 bytes");

        // Calculate message hash (if needed)
        bytes32 messageHash = keccak256(message);

        (bool success, bytes memory result) = ED25519_PRECOMPILE.staticcall(
            abi.encode(publicKey, messageHash, signature)
        );

        return success && abi.decode(result, (bool));
    }

    /**
     * @dev Verify prefixed message signature (recommended)
     */
    function verifySignedMessage(
        bytes32 publicKey,
        string memory message,
        bytes calldata signature
    ) public view returns (bool) {
        // Add Ethereum signature standard prefix to prevent replay attacks
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", bytes(Strings.toString(bytes(message).length)), message)
        );

        return verifyEd25519(publicKey, abi.encodePacked(prefixedHash), signature);
    }

    /**
     * @dev Calculate message hash
     * @param message Original message (arbitrary length)
     * @return bytes32 Message hash
     */
    function calculateMessageHash(bytes memory message) public pure returns (bytes32) {
        return  keccak256(message);
    }

     /**
     * @dev Calculate message hash
     * @param message Original message (arbitrary length)
     * @return bytes32 Message hash
     */
    function calculateSignedMessageHash(string memory message) public pure returns (bytes32) {
        return  keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", bytes(Strings.toString(bytes(message).length)), message));
    }

    /**
     * @dev Call Ed25519 precompile contract
     * @param publicKey 32-byte Ed25519 public key
     * @param messageHash Message hash
     * @param signature 64-byte signature (R||S)
     * @return bool Whether successful
     * @return bool Whether supported
     */
    function staticcallEd25519(bytes32 publicKey, bytes32 messageHash, bytes memory signature) public view returns (bool, bool) {
        (bool success, bytes memory result) = ED25519_PRECOMPILE.staticcall(
            abi.encode(publicKey, messageHash, signature)
        );
        return (success, abi.decode(result, (bool)));
    }
}