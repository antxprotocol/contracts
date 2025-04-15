// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
/**
  An Operator may be instantly appointed or removed by the contract Owner
*/
contract Operator is Ownable{
    event LogOperatorAdded(address operator);
    event LogOperatorRemoved(address operator);
    mapping(address => bool) public operators;

    modifier onlyOperator() {
        require(isOperator(msg.sender), "ONLY_OPERATOR");
        _;
    }

    constructor() Ownable(msg.sender) {
        operators[msg.sender] = true;
        emit LogOperatorAdded(msg.sender);
    }

    function registerOperator(address newOperator) external onlyOwner {
        operators[newOperator] = true;
        emit LogOperatorAdded(newOperator);
    }

    function unregisterOperator(address removedOperator) external onlyOwner {
        operators[removedOperator] = false;
        emit LogOperatorRemoved(removedOperator);
    }

    function isOperator(address testedOperator) public view returns (bool) {
        return operators[testedOperator];
    }

}