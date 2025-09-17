// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract Ed25519SignatureValidation is Ownable {
    // Store verification results
    mapping(bytes32 => bool) public verifiedMessages;
    address public signatureValidationOperator;

    error OnlySignatureValidationOperator();

    modifier onlySignatureValidationOperator() {
        if (msg.sender != signatureValidationOperator) revert OnlySignatureValidationOperator();
        _;
    }

    constructor(address _signatureValidationOperator) Ownable(msg.sender) {
        signatureValidationOperator = _signatureValidationOperator;
        
    }

    function setSignatureValidationOperator(address _signatureValidationOperator) public onlyOwner {
        signatureValidationOperator = _signatureValidationOperator;
    }

    // Submit verification result
    function submitVerification(
        bytes32 publicKey,
        bytes32 messageHash,
        bytes calldata signature,
        bool isValid) public onlySignatureValidationOperator {
        verifiedMessages[keccak256(abi.encodePacked(publicKey, messageHash, signature))] = isValid;
    }

    // Query if verified
    function isVerified(
        bytes32 publicKey,
        bytes32 messageHash,
        bytes calldata signature) public view returns (bool) {
        return verifiedMessages[keccak256(abi.encodePacked(publicKey, messageHash, signature))];
    }
}
