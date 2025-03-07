// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./interfaces/IAsset.sol";
import "./Settlement.sol";

contract SettlementForTest is Settlement {
    constructor(address _assetContract, address[] memory _batchSubmitter) Settlement(_assetContract, _batchSubmitter) {
    }

    function addUserBalanceForTest(address user, uint256 amount) onlyOwner public {
        IAsset(assetContract).addUserBalance(user, amount);
    }

    function addFeeBalanceForTest(uint256 amount) onlyOwner public {
        IAsset(assetContract).addFeeBalance(amount);
    }

    function subUserBalanceForTest(address user, uint256 amount) onlyOwner public {
        IAsset(assetContract).subUserBalance(user, amount);
    }
}
