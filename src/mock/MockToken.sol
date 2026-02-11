// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockToken is ERC20 {
    bool public shouldFailTransfers;

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000000000000000000000);
        shouldFailTransfers = false;
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    // Set flag to determine whether transfers should fail
    function setFailTransfers(bool _shouldFail) public {
        shouldFailTransfers = _shouldFail;
    }

    // Override the native transfer method to support simulated failures
    function transfer(address to, uint256 amount) public override returns (bool) {
        if (shouldFailTransfers) {
            return false;
        }
        return super.transfer(to, amount);
    }

    // Override the transferFrom method to support simulated failures
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (shouldFailTransfers) {
            return false;
        }
        return super.transferFrom(from, to, amount);
    }
}
