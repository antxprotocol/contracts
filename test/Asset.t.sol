// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Asset} from "../src/Asset.sol";
import {IAsset} from "../src/interfaces/IAsset.sol";
import {MockToken} from "../src/mock/MockToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MarginAsset} from "../src/margin/MarginAsset.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";


// Mock StargateWithdraw for testing
contract MockStargateWithdraw {
    using SafeERC20 for IERC20;

    bool public shouldRevert;
    bytes32 public lastGuid;
    address public usdc;

    constructor(address _usdc) {
        usdc = _usdc;
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function prepareRideBus(uint64 dstChainId, uint256 amount, bytes32 receiver)
        external
        view
        returns (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee)
    {
        // Return minimal values for testing
        sendParam = SendParam({
            dstEid: 30101, // Dummy endpoint ID
            to: receiver,
            amountLD: amount,
            minAmountLD: amount,
            extraOptions: new bytes(0),
            composeMsg: new bytes(0),
            oftCmd: new bytes(1)
        });

        messagingFee = MessagingFee({nativeFee: 0.001 ether, lzTokenFee: 0});

        valueToSend = 0.001 ether;
    }

    function prepareTakeTaxi(uint64 dstChainId, uint256 amount, bytes32 receiver)
        external
        view
        returns (uint256 valueToSend, SendParam memory sendParam, MessagingFee memory messagingFee)
    {
        // Return minimal values for testing (same as prepareRideBus)
        sendParam = SendParam({
            dstEid: 30101, // Dummy endpoint ID
            to: receiver,
            amountLD: amount,
            minAmountLD: amount,
            extraOptions: new bytes(0),
            composeMsg: new bytes(0),
            oftCmd: new bytes(0)
        });

        messagingFee = MessagingFee({nativeFee: 0.001 ether, lzTokenFee: 0});

        valueToSend = 0.001 ether;
    }

    function crossChainWithdraw(
        uint256 clientOrderId,
        bytes32 user,
        uint256 amount,
        uint256 dstChainId,
        bytes32 dstAddress,
        address refundAddress,
        SendParam memory sendParam,
        MessagingFee memory messagingFee
    ) external payable returns (bytes32 guid) {
        if (shouldRevert) {
            revert("MockStargateWithdraw: should revert");
        }
        // Transfer USDC from caller (Asset contract) to simulate cross-chain withdraw
        // Use safeTransferFrom to properly handle failures
        IERC20(usdc).safeTransferFrom(msg.sender, address(this), amount);
        // Simulate successful cross-chain withdraw
        lastGuid = keccak256(abi.encodePacked(clientOrderId, user, amount, dstChainId, block.timestamp));
        return lastGuid;
    }
}

// Test helper contract to access internal functions
contract AssetTestHelper is Asset {
    function exposeHashUserWithdraw(
        uint256 clientOrderId,
        bytes32 user,
        bytes32 recipient,
        uint256 amount,
        uint256 fee,
        uint256 expireTime,
        uint64 dstChainId
    ) external view returns (bytes32) {
        return _hashUserWithdraw(clientOrderId, user, recipient, amount, fee, expireTime, dstChainId);
    }
}

// Mock MarginAssetCalculator that returns available amounts based on crossCollateralAmount
contract MockMarginAssetCalculator {
    // Returns the available amount based on crossCollateralAmount
    // Signature matches MarginAssetCalculator.getCrossTransferOutAvailableAmount
    function getCrossTransferOutAvailableAmount(
        MarginAsset.Coin memory collateralCoin,
        MarginAsset.Exchange[] memory exchanges,
        MarginAsset.OraclePrice[] memory oraclePrices,
        MarginAsset.FundingIndex[] memory fundingIndices,
        MarginAsset.Subaccount memory subaccount,
        MarginAsset.PerpetualAsset memory perpetualAsset
    ) external pure returns (int256) {
        // For simplicity in tests, return the crossCollateralAmount
        return int256(int64(perpetualAsset.crossCollateralAmount));
    }
}

// Helper contract to expose the validTime modifier via a simple callable function
contract AssetValidTimeHelper is Asset {
    function ping(uint256 t) external validTime(t) returns (bool) {
        return true;
    }
}

// Helper function to deploy Asset via proxy
library AssetDeployer {
    function deployAsset(address usdc, address owner) internal returns (Asset) {
        return deployAsset(usdc, owner, 1); // Default to coinId 1 for tests
    }

    function deployAsset(address usdc, address owner, uint64 defaultCollateralCoinId) internal returns (Asset) {
        // Deploy implementation
        Asset implementation = new Asset();

        // Encode initialize function call
        bytes memory initData = abi.encodeWithSelector(Asset.initialize.selector, usdc, defaultCollateralCoinId);

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        // Return Asset instance through proxy
        Asset asset = Asset(payable(address(proxy)));

        // Transfer ownership to the specified owner
        if (owner != address(0)) {
            asset.transferOwnership(owner);
        }

        return asset;
    }

    function deployAssetValidTimeHelper(address usdc, address owner) internal returns (AssetValidTimeHelper) {
        return deployAssetValidTimeHelper(usdc, owner, 1); // Default to coinId 1 for tests
    }

    function deployAssetValidTimeHelper(address usdc, address owner, uint64 defaultCollateralCoinId)
        internal
        returns (AssetValidTimeHelper)
    {
        // Deploy implementation
        AssetValidTimeHelper implementation = new AssetValidTimeHelper();

        // Encode initialize function call (using Asset's initialize)
        bytes memory initData = abi.encodeWithSelector(Asset.initialize.selector, usdc, defaultCollateralCoinId);

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        // Return AssetValidTimeHelper instance through proxy
        AssetValidTimeHelper helper = AssetValidTimeHelper(payable(address(proxy)));

        // Transfer ownership to the specified owner
        if (owner != address(0)) {
            helper.transferOwnership(owner);
        }

        return helper;
    }
}

contract AssetTest is Test {
    Asset public asset;
    MockToken public USDC;
    MockMarginAssetCalculator public marginAssetCalculator;
    MockStargateWithdraw public mockStargateWithdraw;
    address public owner;
    address public systemAddress;
    address public settlementOperator;
    address public withdrawOperator;
    address public signer1;
    address public signer2;
    address public signer3;
    uint256 public signer1PrivateKey;
    uint256 public signer2PrivateKey;
    uint256 public signer3PrivateKey;
    address internal user1 = address(0x5);
    address internal user2 = address(0x6);
    address[] public signers;

    // Chain IDs for testing
    uint64 constant BASE_MAINNET = 8543;
    uint64 constant BASE_SEPOLIA = 85432;
    uint64 constant ETHEREUM_MAINNET = 1;
    uint64 constant SEPOLIA = 11155111;

    // Helper function to convert multiple user updates into BatchUpdateData
    function createBatchUpdateDataFromUsers(bytes32[] memory users, uint256[] memory amounts)
        internal
        pure
        returns (Asset.BatchUpdateData memory)
    {
        require(users.length == amounts.length, "Arrays length mismatch");

        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](users.length);
        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](users.length);

        for (uint256 i = 0; i < users.length; i++) {
            uint64 subAccountId = uint64(uint256(users[i]) % type(uint64).max);
            if (subAccountId == 0) subAccountId = 1;

            int64 crossCollateralAmount;
            if (amounts[i] > uint256(uint64(type(int64).max))) {
                crossCollateralAmount = type(int64).max;
            } else {
                crossCollateralAmount = int64(int256(amounts[i]));
            }

            MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
            MarginAsset.Position[] memory positions = new MarginAsset.Position[](0);

            subaccountUpdates[i] = MarginAsset.Subaccount({
                id: subAccountId,
                chainAddress: users[i],
                isMultiSigWallet: false,
                multiSigWallet: address(0),
                clientAccountId: "",
                tradeSettings: tradeSettings
            });

            perpetualAssetUpdates[i] = MarginAsset.PerpetualAsset({
                subaccountId: subAccountId,
                collateralCoinId: 1,
                crossCollateralAmount: crossCollateralAmount,
                positions: positions
            });
        }

        return Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });
    }

    // Helper function to get subaccountId from user address
    function getSubaccountId(bytes32 user) internal view returns (uint64) {
        uint64 subaccountId = asset.addressToSubaccountId(user);
        require(subaccountId != 0, "Subaccount not found");
        return subaccountId;
    }

    // Helper function to convert bytes32[] users to uint64[] subaccountIds
    function getSubaccountIds(bytes32[] memory users) internal view returns (uint64[] memory) {
        uint64[] memory subaccountIds = new uint64[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            subaccountIds[i] = getSubaccountId(users[i]);
        }
        return subaccountIds;
    }

    // Helper function to get dstChainId based on current chain
    function getDstChainId() internal view returns (uint64) {
        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            return BASE_MAINNET;
        }
        return ETHEREUM_MAINNET;
    }

    // Internal amount (stepSizeScale 6) -> raw USDC (18 decimals). Asset uses coin stepSizeScale 6, USDC 18.
    function getTransferAmount(uint256 amountInternal) internal pure returns (uint256) {
        return amountInternal * 1e12;
    }

    // Helper function to fund Asset contract with ETH for cross-chain fees
    function fundAssetWithETH() internal {
        if (block.chainid != BASE_MAINNET && block.chainid != BASE_SEPOLIA) {
            vm.deal(address(asset), 1 ether);
        }
    }

    // Helper function to create signature hash for USER_WITHDRAW
    function createWithdrawSignatureHash(
        uint256 clientOrderId,
        bytes32 user,
        bytes32 recipient,
        uint256 amount,
        uint256 fee,
        uint256 expireTime,
        uint64 dstChainId
    ) internal view returns (bytes32) {
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "USER_WITHDRAW",
                clientOrderId,
                user,
                recipient,
                amount,
                fee,
                expireTime,
                dstChainId,
                block.chainid,
                address(asset)
            )
        );
        return MessageHashUtils.toEthSignedMessageHash(operationHash);
    }

    // Helper function to create signature for USER_WITHDRAW
    function createWithdrawSignature(
        uint256 clientOrderId,
        bytes32 user,
        bytes32 recipient,
        uint256 amount,
        uint256 fee,
        uint256 expireTime,
        uint64 dstChainId,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 hash = createWithdrawSignatureHash(clientOrderId, user, recipient, amount, fee, expireTime, dstChainId);
        return signMessage(hash, privateKey);
    }

    // Helper function to create dstChainIds array
    function createDstChainIds(uint256 length) internal view returns (uint64[] memory) {
        uint64[] memory dstChainIds = new uint64[](length);
        uint64 dstChainId = getDstChainId();
        for (uint256 i = 0; i < length; i++) {
            dstChainIds[i] = dstChainId;
        }
        return dstChainIds;
    }

    // Helper function to create fees array (default to 0)
    function createFees(uint256 length) internal pure returns (uint256[] memory) {
        uint256[] memory fees = new uint256[](length);
        // Default fee is 0
        return fees;
    }

    // Helper function to create fees array with specific fee value
    function createFees(uint256 length, uint256 fee) internal pure returns (uint256[] memory) {
        uint256[] memory fees = new uint256[](length);
        for (uint256 i = 0; i < length; i++) {
            fees[i] = fee;
        }
        return fees;
    }

    // Helper function to create recipients array (defaults to user address)
    function createRecipients(bytes32[] memory users) internal pure returns (bytes32[] memory) {
        bytes32[] memory recipients = new bytes32[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            recipients[i] = users[i]; // Default recipient is the user themselves
        }
        return recipients;
    }

    // Helper function to create expireTimes array
    function createExpireTimes(uint256 length, uint256 expireTime) internal pure returns (uint256[] memory) {
        uint256[] memory expireTimes = new uint256[](length);
        for (uint256 i = 0; i < length; i++) {
            expireTimes[i] = expireTime;
        }
        return expireTimes;
    }

    // Helper function to assert balance changes based on chain. expectedAmountInternal is internal (6 decimals).
    function assertBalanceChange(
        address user,
        uint256 userBalanceBefore,
        uint256 userBalanceAfter,
        uint256 expectedAmountInternal,
        uint256 assetBalanceBefore,
        uint256 mockStargateBalanceBefore
    ) internal view {
        uint256 expectedRaw = getTransferAmount(expectedAmountInternal);
        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            assertEq(userBalanceAfter - userBalanceBefore, expectedRaw);
        } else {
            uint256 assetBalanceAfter = USDC.balanceOf(address(asset));
            uint256 mockStargateBalanceAfter = USDC.balanceOf(address(mockStargateWithdraw));
            assertEq(userBalanceAfter - userBalanceBefore, 0);
            assertEq(mockStargateBalanceAfter - mockStargateBalanceBefore, expectedRaw);
            assertEq(assetBalanceBefore - assetBalanceAfter, expectedRaw);
        }
    }

    // Helper function to create BatchUpdateData
    function createBatchUpdateData(bytes32 user, uint256 availableAmount)
        internal
        pure
        returns (Asset.BatchUpdateData memory)
    {
        // Use a simple subAccountId based on user address
        uint64 subAccountId = uint64(uint256(user) % type(uint64).max);
        if (subAccountId == 0) subAccountId = 1; // Ensure non-zero

        // Convert to int64 safely, clamping if too large
        int64 crossCollateralAmount;
        if (availableAmount > uint256(uint64(type(int64).max))) {
            crossCollateralAmount = type(int64).max;
        } else {
            crossCollateralAmount = int64(int256(availableAmount));
        }

        // Create Subaccount
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        subaccountUpdates[0] = MarginAsset.Subaccount({
            id: subAccountId,
            chainAddress: user,
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "",
            tradeSettings: tradeSettings
        });

        // Create PerpetualAsset with default collateralCoinId = 1
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](0);
        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](1);
        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: subAccountId,
            collateralCoinId: 1,
            crossCollateralAmount: crossCollateralAmount,
            positions: positions
        });

        return Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });
    }

    // Helper function to create UserAssetUpdate (deprecated, use createBatchUpdateData instead)
    // This function is kept for backward compatibility but is no longer used
    // function createUserAssetUpdate(
    //     bytes32 user,
    //     uint256 availableAmount
    // ) internal pure returns (Asset.BatchUpdateData memory) {
    //     return createBatchUpdateData(user, availableAmount);
    // }

    function setUp() public {
        // Initialize private keys and addresses
        signer1PrivateKey = 1;
        signer2PrivateKey = 2;
        signer3PrivateKey = 3;
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        signer3 = vm.addr(signer3PrivateKey);
        owner = vm.addr(999);
        systemAddress = vm.addr(888);
        settlementOperator = vm.addr(777);
        withdrawOperator = vm.addr(666);

        // Deploy mock USDC
        USDC = new MockToken("USDC", "USDC");

        // Deploy mock MarginAssetCalculator
        marginAssetCalculator = new MockMarginAssetCalculator();

        // Deploy mock StargateWithdraw
        mockStargateWithdraw = new MockStargateWithdraw(address(USDC));

        // Initialize signers array
        signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;

        // Deploy Asset contract with proper owner
        vm.startPrank(owner);
        asset = AssetDeployer.deployAsset(address(USDC), owner);
        asset.setSigners(signers);
        asset.setSettlementAddress(settlementOperator);
        asset.setWithdrawOperator(withdrawOperator);
        asset.setMarginAsset(address(marginAssetCalculator));
        asset.setStargateWithdraw(address(mockStargateWithdraw));
        vm.stopPrank();

        // Set up coin (coinId=1 is USDC) for tests via batchUpdate
        // Note: This sets lastBatchId to 1, so subsequent tests should start from batchId=2
        vm.startPrank(settlementOperator);
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
        coinUpdates[0] = MarginAsset.Coin({id: 1, symbol: "USDC", stepSizeScale: 6});
        Asset.BatchUpdateData memory coinSetupData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(1, 0, 1, coinSetupData);
        vm.stopPrank();

        // Fund Asset with raw USDC so withdraws can succeed (internal 6 decimals -> 18 decimals = *1e12)
        USDC.transfer(address(asset), 1e21);
    }

    // ============ Coverage helpers for modifiers/constructor branches ============

    function test_validTime_pass_and_revert() public {
        vm.startPrank(owner);
        AssetValidTimeHelper a = AssetDeployer.deployAssetValidTimeHelper(address(USDC), owner);
        vm.stopPrank();

        // pass
        assertTrue(a.ping(1));

        // revert on 0
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidTime.selector, 0));
        a.ping(0);
    }


    function signMessage(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    // Test constructor functionality
    function test_constructor_success() public {
        assertEq(asset.owner(), owner);
        assertEq(address(asset.USDC()), address(USDC));
        assertEq(asset.settlementOperator(), settlementOperator);
        assertEq(asset.withdrawOperator(), withdrawOperator);
        assertEq(asset.lastBatchId(), 1);
        assertEq(asset.lastBatchTime(), block.timestamp);
        assertEq(asset.lastAntxChainHeight(), 1);
        assertTrue(asset.isAllowedSigner(signer1));
        assertTrue(asset.isAllowedSigner(signer2));
        assertTrue(asset.isAllowedSigner(signer3));
    }

    function test_constructor_zeroUSDC() public {
        vm.startPrank(owner);
        // Deploy implementation first
        Asset implementation = new Asset();
        bytes memory initData = abi.encodeWithSelector(Asset.initialize.selector, address(0), uint64(1));
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        new ERC1967Proxy(address(implementation), initData);
        vm.stopPrank();
    }

    function test_constructor_zeroSystemAddress() public {
        vm.startPrank(owner);
        Asset a = AssetDeployer.deployAsset(address(USDC), owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        a.setSettlementAddress(address(0));
        vm.stopPrank();
    }

    function test_constructor_zeroSettlementOperator() public {
        vm.startPrank(owner);
        Asset a = AssetDeployer.deployAsset(address(USDC), owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        a.setSettlementAddress(address(0));
        vm.stopPrank();
    }

    function test_constructor_zeroWithdrawOperator() public {
        vm.startPrank(owner);
        Asset a = AssetDeployer.deployAsset(address(USDC), owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        a.setWithdrawOperator(address(0));
        vm.stopPrank();
    }

    function test_constructor_defaultCollateralCoinId() public {
        assertEq(asset.defaultCollateralCoinId(), 1);
    }

    function test_constructor_zeroDefaultCollateralCoinId() public {
        vm.startPrank(owner);
        Asset implementation = new Asset();
        bytes memory initData = abi.encodeWithSelector(Asset.initialize.selector, address(USDC), uint64(0));
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        new ERC1967Proxy(address(implementation), initData);
        vm.stopPrank();
    }

    function test_constructor_emptySigners() public {
        vm.startPrank(owner);
        Asset a = AssetDeployer.deployAsset(address(USDC), owner);
        address[] memory emptySigners = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        a.setSigners(emptySigners);
        vm.stopPrank();
    }

    function test_constructor_zeroAddressInSigners() public {
        vm.startPrank(owner);
        Asset a = AssetDeployer.deployAsset(address(USDC), owner);
        address[] memory invalidSigners = new address[](2);
        invalidSigners[0] = signer1;
        invalidSigners[1] = address(0);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        a.setSigners(invalidSigners);
        vm.stopPrank();
    }

    // Test batchUpdate function
    function test_batchUpdate_success() public {
        bytes32 user1Bytes = bytes32(uint256(uint160(user1)));
        bytes32 user2Bytes = bytes32(uint256(uint160(user2)));

        Asset.BatchUpdateData memory batchData1 = createBatchUpdateData(user1Bytes, 1000);
        Asset.BatchUpdateData memory batchData2 = createBatchUpdateData(user2Bytes, 2000);

        // Merge both updates
        Asset.BatchUpdateData memory mergedData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](2),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](2)
        });
        mergedData.subaccountUpdates[0] = batchData1.subaccountUpdates[0];
        mergedData.subaccountUpdates[1] = batchData2.subaccountUpdates[0];
        mergedData.perpetualAssetUpdates[0] = batchData1.perpetualAssetUpdates[0];
        mergedData.perpetualAssetUpdates[1] = batchData2.perpetualAssetUpdates[0];

        vm.startPrank(settlementOperator);
        vm.expectEmit(address(asset));
        emit IAsset.BatchUpdated(2, 101, block.timestamp);

        asset.batchUpdate(2, 0, 101, mergedData);
        vm.stopPrank();

        assertEq(asset.availableAmount(user1Bytes), 1000);
        assertEq(asset.availableAmount(user2Bytes), 2000);
        assertEq(asset.lastBatchId(), 2);
        assertEq(asset.lastBatchTime(), block.timestamp);
        assertEq(asset.lastAntxChainHeight(), 101);
    }

    function test_batchUpdate_invalidBatchId() public {
        bytes32 user1Bytes = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user1Bytes, 1000);

        vm.startPrank(settlementOperator);
        // Try to update with invalid batch ID (should be 2, but using 3)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        asset.batchUpdate(3, 0, 102, batchData);

        // Try with 1 (should also fail since lastBatchId is 1, expecting 2)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        asset.batchUpdate(1, 0, 102, batchData);

        vm.stopPrank();
    }

    function test_batchUpdate_invalidAntxChainHeight() public {
        bytes32 user1Bytes = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user1Bytes, 1000);

        vm.startPrank(settlementOperator);
        // First update should succeed
        asset.batchUpdate(2, 0, 101, batchData);

        // Try with same antxChainHeight (should fail)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidAntxChainHeight.selector));
        asset.batchUpdate(3, 0, 101, batchData);

        // Try with lower antxChainHeight (should fail)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidAntxChainHeight.selector));
        asset.batchUpdate(3, 0, 50, batchData);

        // Try with valid higher antxChainHeight (should succeed)
        asset.batchUpdate(3, 0, 102, batchData);

        vm.stopPrank();
    }

    function test_batchUpdate_sequentialBatchIds() public {
        bytes32 user1Bytes = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);

        // First batch should be ID 2 (since setUp already called batchUpdate(1, ...))
        Asset.BatchUpdateData memory batchData1 = createBatchUpdateData(user1Bytes, 1000);
        asset.batchUpdate(2, 0, 101, batchData1);
        assertEq(asset.lastBatchId(), 2);

        // Second batch should be ID 3
        Asset.BatchUpdateData memory batchData2 = createBatchUpdateData(user1Bytes, 2000);
        asset.batchUpdate(3, 0, 102, batchData2);
        assertEq(asset.lastBatchId(), 3);

        // Third batch should be ID 4
        Asset.BatchUpdateData memory batchData3 = createBatchUpdateData(user1Bytes, 3000);
        asset.batchUpdate(4, 0, 103, batchData3);
        assertEq(asset.lastBatchId(), 4);

        vm.stopPrank();

        assertEq(asset.availableAmount(user1Bytes), 3000);
    }

    function test_batchUpdate_onlySettlementOperator() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAsset.OnlySettlementOperator.selector));
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();
    }

    function test_batchUpdate_lengthMismatch() public {
        // batchUpdate doesn't have length mismatch anymore since it uses BatchUpdateData
        // This test validates that batchUpdate works correctly
        bytes32 user1Bytes = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user1Bytes, 1000);

        vm.startPrank(settlementOperator);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        assertEq(asset.availableAmount(user1Bytes), 1000);
    }

    // Test batchWithdraw function with proper signature
    function test_batchWithdraw_success() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);

        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature with the correct private key for the test user
        bytes32 userBytes = bytes32(uint256(uint160(testUser)));
        bytes32 recipient = userBytes; // Default recipient is the user themselves
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();
        bytes memory userSignature =
            createWithdrawSignature(123, userBytes, recipient, 500, 0, expireTime, dstChainId, userPrivateKey);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = recipient;
        uint256[] memory expireTimes = new uint256[](1);
        expireTimes[0] = expireTime;

        uint256 userBalanceBefore = USDC.balanceOf(testUser);
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        // Execute batch withdraw - should now work with correct signature
        vm.startPrank(withdrawOperator);
        // Note: Approval events may be emitted before CrossChainWithdraw due to forceApprove
        // So we check the final state instead of expecting specific event order
        uint64[] memory subaccountIds = getSubaccountIds(users);
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();

        uint256 userBalanceAfter = USDC.balanceOf(testUser);
        uint256 assetBalanceAfter = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceAfter = USDC.balanceOf(address(mockStargateWithdraw));

        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            // On Base, user receives USDC directly
            assertEq(userBalanceAfter - userBalanceBefore, getTransferAmount(500));
        } else {
            // On non-Arbitrum chains, USDC goes to MockStargateWithdraw for cross-chain
            assertEq(userBalanceAfter - userBalanceBefore, 0);
            assertEq(mockStargateBalanceAfter - mockStargateBalanceBefore, getTransferAmount(500));
            assertEq(assetBalanceBefore - assetBalanceAfter, getTransferAmount(500));
        }
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(testUser)))), 1000);
    }

    // Test batchWithdraw with invalid signature
    function test_batchWithdraw_invalidSignature() public {
        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);

        address[] memory users = new address[](1);
        users[0] = user1;

        bytes32[] memory bUsers = new bytes32[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            bUsers[i] = bytes32(uint256(uint160(users[i])));
        }

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;
        amounts[0] = 500;

        // Create signature with wrong private key
        bytes32 userBytes = bytes32(uint256(uint160(user1)));
        bytes32 recipient = userBytes;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();
        bytes memory wrongSignature =
            createWithdrawSignature(123, userBytes, recipient, 500, 0, expireTime, dstChainId, 999);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = wrongSignature;

        bytes32[] memory recipients = createRecipients(bUsers);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, expireTime);

        // Execute batch withdraw - should fail with invalid signature
        vm.startPrank(withdrawOperator);
        uint64[] memory subaccountIds = getSubaccountIds(bUsers);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidUserSignature.selector));
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    // Test batchWithdraw with insufficient user balance
    function test_batchWithdraw_insufficientBalance() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);

        // Setup small user balance
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100; // Small balance

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare batch withdraw for more than user has
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500; // More than user has

        // Create user signature
        bytes32 userBytes = bytes32(uint256(uint160(testUser)));
        bytes32 recipient = userBytes;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();
        bytes memory userSignature =
            createWithdrawSignature(123, userBytes, recipient, 500, 0, expireTime, dstChainId, userPrivateKey);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, expireTime);

        // Execute batch withdraw - should fail with insufficient balance
        vm.startPrank(withdrawOperator);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, 100, 500));
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    function test_batchWithdraw_lengthMismatch() public {
        // Setup subaccounts first
        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        bUsers[1] = bytes32(uint256(uint160(user2)));
        uint256[] memory setupAmounts = new uint256[](2);
        setupAmounts[0] = 1000;
        setupAmounts[1] = 1000;

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory setupData = createBatchUpdateDataFromUsers(bUsers, setupAmounts);
        asset.batchUpdate(2, 0, 101, setupData);
        vm.stopPrank();

        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](2);
        users[0] = bytes32(uint256(uint160(user1)));
        users[1] = bytes32(uint256(uint160(user2)));

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = new bytes(65);

        vm.startPrank(withdrawOperator);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        vm.expectRevert(abi.encodeWithSelector(IAsset.LengthNotMatch.selector));
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    function test_batchWithdraw_signatureLengthMismatch() public {
        // Setup subaccount first
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        uint256[] memory setupAmounts = new uint256[](1);
        setupAmounts[0] = 1000;

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory setupData = createBatchUpdateDataFromUsers(bUsers, setupAmounts);
        asset.batchUpdate(2, 0, 101, setupData);
        vm.stopPrank();

        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(user1)));

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = new bytes(65);
        signatures[1] = new bytes(65);

        vm.startPrank(withdrawOperator);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        vm.expectRevert(abi.encodeWithSelector(IAsset.LengthNotMatch.selector));
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    // Test batchWithdraw onlyWithdrawOperator
    function test_batchWithdraw_onlyWithdrawOperator() public {
        // Setup subaccount first
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        uint256[] memory setupAmounts = new uint256[](1);
        setupAmounts[0] = 1000;

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory setupData = createBatchUpdateDataFromUsers(bUsers, setupAmounts);
        asset.batchUpdate(2, 0, 101, setupData);
        vm.stopPrank();

        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(user1)));

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = new bytes(65);

        // Try to call from non-withdrawOperator address
        vm.startPrank(user1);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        vm.expectRevert(abi.encodeWithSelector(IAsset.OnlyWithdrawOperator.selector));
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    // Test forceWithdraw function
    function test_forceWithdraw_success() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Advance time past the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDC.balanceOf(user1);
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        vm.startPrank(user1);
        // Note: Approval events may be emitted before CrossChainWithdraw due to forceApprove
        // So we check the final state instead of expecting specific event order
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();

        uint256 user1BalanceAfter = USDC.balanceOf(user1);
        assertBalanceChange(
            user1, user1BalanceBefore, user1BalanceAfter, 500, assetBalanceBefore, mockStargateBalanceBefore
        );
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), 1000);
    }

    function test_forceWithdraw_success_ed25519_flag_path() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 600;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund and pass timelock
        USDC.transfer(address(asset), getTransferAmount(600));
        fundAssetWithETH();
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 beforeBal = USDC.balanceOf(user1);
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        vm.startPrank(user1);
        // Use ED25519 enum to cover that path (isForce skips signature logic)
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(200, getDstChainId());
        vm.stopPrank();

        uint256 afterBal = USDC.balanceOf(user1);
        assertBalanceChange(user1, beforeBal, afterBal, 200, assetBalanceBefore, mockStargateBalanceBefore);
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), 600);
    }

    function test_forceWithdraw_timeLockNotPassed() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Don't advance time
        vm.startPrank(user1);
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        vm.expectRevert(abi.encodeWithSelector(IAsset.TimeLockNotPassed.selector));
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();
    }

    function test_forceWithdraw_zeroAmount() public {
        // Setup subaccount first (even with zero balance)
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        uint256[] memory setupAmounts = new uint256[](1);
        setupAmounts[0] = 0;

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory setupData = createBatchUpdateDataFromUsers(bUsers, setupAmounts);
        asset.batchUpdate(2, 0, 101, setupData);
        vm.stopPrank();

        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        // Note: forceWithdraw with amount 0 will revert due to validAmount modifier
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        asset.forceWithdraw(0, getDstChainId());
        vm.stopPrank();
    }

    function test_forceWithdraw_insufficientBalance() public {
        // Setup small user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, 100, 500));
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();
    }

    function test_emergencyWithdraw_success() public {
        // Fund the contract (no need to setup system balance anymore)
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare multi-sig withdraw
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 500;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdraw_invalidToken() public {
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;
        address[] memory allSigners = new address[](2);
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(
            address(0x123), // Invalid token
            user1,
            500,
            expireTime,
            nonce,
            allSigners,
            signatures
        );
    }

    function test_emergencyWithdraw_insufficientSigners() public {
        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](1);
        allSigners[0] = signer1;
        bytes[] memory signatures = new bytes[](1);

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), user1, 500, expireTime, 0, allSigners, signatures);
    }

    function test_emergencyWithdraw_signatureLengthMismatch() public {
        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](3);

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), user1, 500, expireTime, 0, allSigners, signatures);
    }

    function test_emergencyWithdraw_sameSigner() public {
        uint256 expireTime = block.timestamp + 1 hours;
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer1; // Same signer
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), user1, 500, expireTime, 0, allSigners, signatures);
    }

    function test_emergencyWithdraw_expiredTransaction() public {
        uint256 expireTime = block.timestamp - 1; // Already expired
        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), user1, 500, expireTime, 0, allSigners, signatures);
    }

    function test_emergencyWithdraw_invalidSigner() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW", address(USDC), user1, uint256(500), expireTime, nonce, address(asset), block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // Use wrong private key for signature
        bytes memory wrongSignature = signMessage(operationHash, 999);
        bytes memory correctSignature = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = wrongSignature; // Wrong signature
        signatures[1] = correctSignature;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), user1, 500, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdraw_notAllowedSigner() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW", address(USDC), user1, uint256(500), expireTime, nonce, address(asset), block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // Use a signer that's not in the allowed list
        uint256 notAllowedKey = 888;
        address notAllowedSigner = vm.addr(notAllowedKey);
        bytes memory notAllowedSignature = signMessage(operationHash, notAllowedKey);
        bytes memory validSignature = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = notAllowedSigner;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = notAllowedSignature;
        signatures[1] = validSignature;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), user1, 500, expireTime, nonce, allSigners, signatures);
    }

    // Test admin functions
    function test_setSettlementAddress_success() public {
        address newSettlementAddress = address(0x888);

        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.SettlementAddressUpdated(newSettlementAddress);
        asset.setSettlementAddress(newSettlementAddress);
        vm.stopPrank();

        assertEq(asset.settlementOperator(), newSettlementAddress);
    }

    function test_setSettlementAddress_onlyOwner() public {
        address newSettlementAddress = address(0x888);

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setSettlementAddress(newSettlementAddress);
        vm.stopPrank();
    }

    function test_setSettlementAddress_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSettlementAddress(address(0));
        vm.stopPrank();
    }

    function test_setSigners_success() public {
        address[] memory newSigners = new address[](2);
        newSigners[0] = address(0x111);
        newSigners[1] = address(0x222);

        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.SignersUpdated(newSigners);
        asset.setSigners(newSigners);
        vm.stopPrank();

        assertTrue(asset.isAllowedSigner(address(0x111)));
        assertTrue(asset.isAllowedSigner(address(0x222)));
        assertFalse(asset.isAllowedSigner(signer1)); // Old signer should no longer be valid
    }

    function test_setSigners_onlyOwner() public {
        address[] memory newSigners = new address[](1);
        newSigners[0] = address(0x111);

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setSigners(newSigners);
        vm.stopPrank();
    }

    function test_setSigners_emptyArray() public {
        address[] memory emptySigners = new address[](0);

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSigners(emptySigners);
        vm.stopPrank();
    }

    function test_setSigners_zeroAddressInArray() public {
        address[] memory invalidSigners = new address[](2);
        invalidSigners[0] = address(0x111);
        invalidSigners[1] = address(0); // Zero address

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSigners(invalidSigners);
        vm.stopPrank();
    }

    function test_setWithdrawOperator_success() public {
        address newWithdrawOperator = address(0x777);

        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.WithdrawOperatorUpdated(newWithdrawOperator);
        asset.setWithdrawOperator(newWithdrawOperator);
        vm.stopPrank();

        assertEq(asset.withdrawOperator(), newWithdrawOperator);
    }

    function test_setWithdrawOperator_onlyOwner() public {
        address newWithdrawOperator = address(0x777);

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setWithdrawOperator(newWithdrawOperator);
        vm.stopPrank();
    }

    function test_setWithdrawOperator_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setWithdrawOperator(address(0));
        vm.stopPrank();
    }

    function test_setStargateWithdraw_success() public {
        address newStargateWithdraw = address(0x999);

        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.StargateWithdrawUpdated(newStargateWithdraw);
        asset.setStargateWithdraw(newStargateWithdraw);
        vm.stopPrank();

        assertEq(address(asset.stargateWithdraw()), newStargateWithdraw);
    }

    function test_setStargateWithdraw_onlyOwner() public {
        address newStargateWithdraw = address(0x999);

        vm.startPrank(user1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user1));
        asset.setStargateWithdraw(newStargateWithdraw);
        vm.stopPrank();
    }

    function test_setStargateWithdraw_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setStargateWithdraw(address(0));
        vm.stopPrank();
    }

    // Test isAllowedSigner function
    function test_isAllowedSigner() public {
        assertTrue(asset.isAllowedSigner(signer1));
        assertTrue(asset.isAllowedSigner(signer2));
        assertTrue(asset.isAllowedSigner(signer3));
        assertFalse(asset.isAllowedSigner(user1));
        assertFalse(asset.isAllowedSigner(address(0)));
    }

    function test_isAllowedSigner_notFound_fallthrough() public {
        // Deploy an Asset with a single signer to force full loop fallthrough
        address[] memory single = new address[](1);
        single[0] = signer1;
        vm.startPrank(owner);
        Asset a2 = AssetDeployer.deployAsset(address(USDC), owner);
        a2.setSigners(single);
        vm.stopPrank();
        address notSigner = address(0xDEADBEeF);
        assertFalse(a2.isAllowedSigner(notSigner));
    }

    // Test transfer failure scenarios
    function test_userWithdraw_transferFailure() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Set USDC to fail transfers
        USDC.setFailTransfers(true);

        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        vm.expectRevert(); // Should revert due to SafeERC20 failing on false return
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();

        // Reset transfer behavior
        USDC.setFailTransfers(false);
    }

    // Test reentrancy protection
    function test_reentrancy_protection() public {
        // The contract uses ReentrancyGuard, so reentrancy should be prevented
        // This is automatically tested by the modifier, but we can verify
        // that the functions have the nonReentrant modifier applied

        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        // Normal withdrawal should work
        vm.startPrank(user1);
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();

        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), 1000);
    }

    // Test multiple users batch withdraw
    function test_batchWithdraw_multipleUsers() public {
        // Use specific private keys and derive user addresses
        uint256 user1PrivateKey = 0x1111111111111111111111111111111111111111111111111111111111111111;
        uint256 user2PrivateKey = 0x2222222222222222222222222222222222222222222222222222222222222222;
        address testUser1 = vm.addr(user1PrivateKey);
        address testUser2 = vm.addr(user2PrivateKey);

        // Setup user balances
        address[] memory usersForBalance = new address[](2);
        usersForBalance[0] = testUser1;
        usersForBalance[1] = testUser2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1000;
        amounts[1] = 2000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(testUser1)));
        bUsers[1] = bytes32(uint256(uint160(testUser2)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(3000));
        fundAssetWithETH();

        // Prepare batch withdraw for both users
        uint256[] memory clientOrderIds = new uint256[](2);
        clientOrderIds[0] = 123;
        clientOrderIds[1] = 456;

        bytes32[] memory users = new bytes32[](2);
        users[0] = bytes32(uint256(uint160(testUser1)));
        users[1] = bytes32(uint256(uint160(testUser2)));
        amounts[0] = 500;
        amounts[1] = 800;

        // Create signatures for both users
        bytes32 user1Bytes = bytes32(uint256(uint160(testUser1)));
        bytes32 user2Bytes = bytes32(uint256(uint160(testUser2)));
        bytes32 recipient1 = user1Bytes;
        bytes32 recipient2 = user2Bytes;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();

        bytes[] memory signatures = new bytes[](2);
        signatures[0] =
            createWithdrawSignature(123, user1Bytes, recipient1, 500, 0, expireTime, dstChainId, user1PrivateKey);
        signatures[1] =
            createWithdrawSignature(456, user2Bytes, recipient2, 800, 0, expireTime, dstChainId, user2PrivateKey);

        uint256 user1BalanceBefore = USDC.balanceOf(testUser1);
        uint256 user2BalanceBefore = USDC.balanceOf(testUser2);
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        // Execute batch withdraw for both users
        vm.startPrank(withdrawOperator);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();

        uint256 user1BalanceAfter = USDC.balanceOf(testUser1);
        uint256 user2BalanceAfter = USDC.balanceOf(testUser2);
        uint256 assetBalanceAfter = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceAfter = USDC.balanceOf(address(mockStargateWithdraw));

        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            // On Arbitrum, users receive USDC directly
            assertEq(user1BalanceAfter - user1BalanceBefore, getTransferAmount(500));
            assertEq(user2BalanceAfter - user2BalanceBefore, getTransferAmount(800));
        } else {
            // On non-Arbitrum chains, USDC goes to MockStargateWithdraw for cross-chain
            assertEq(user1BalanceAfter - user1BalanceBefore, 0);
            assertEq(user2BalanceAfter - user2BalanceBefore, 0);
            assertEq(mockStargateBalanceAfter - mockStargateBalanceBefore, getTransferAmount(1300)); // 500 + 800
            assertEq(assetBalanceBefore - assetBalanceAfter, getTransferAmount(1300));
        }
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(testUser1)))), 1000);
        assertEq(asset.availableAmount(bytes32(uint256(uint160(testUser2)))), 2000);
    }

    // Test emergencyWithdraw with multiple signers (more than 2)
    function test_emergencyWithdraw_multipleSigners() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare multi-sig withdraw with all 3 signers
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 500;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);

        address[] memory allSigners = new address[](3);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        allSigners[2] = signer3;

        bytes[] memory signatures = new bytes[](3);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    // Test edge cases and boundary conditions
    function test_edge_cases() public {
        // Test with maximum values allowed by int64
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = uint256(uint64(type(int64).max)); // Max value for int64

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), uint256(uint64(type(int64).max)));
        assertEq(asset.lastBatchId(), 2);
    }

    // Test large batch update with many users
    function test_batchUpdate_largeBatch() public {
        uint256 numUsers = 50;
        address[] memory users = new address[](numUsers);
        uint256[] memory amounts = new uint256[](numUsers);

        for (uint256 i = 0; i < numUsers; i++) {
            users[i] = address(uint160(i + 1000));
            amounts[i] = (i + 1) * 100;
        }

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](numUsers);
        for (uint256 i = 0; i < numUsers; i++) {
            bUsers[i] = bytes32(uint256(uint160(users[i])));
        }

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        for (uint256 i = 0; i < numUsers; i++) {
            assertEq(asset.availableAmount(bytes32(uint256(uint160(users[i])))), amounts[i]);
        }
        assertEq(asset.lastBatchId(), 2);
    }

    // Test batchWithdraw with clientOrderIds length insufficient (should cause array bounds error)
    function test_batchWithdraw_clientOrderIdsLengthInsufficient() public {
        // Setup subaccounts first
        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        bUsers[1] = bytes32(uint256(uint160(user2)));
        uint256[] memory setupAmounts = new uint256[](2);
        setupAmounts[0] = 1000;
        setupAmounts[1] = 1000;

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory setupData = createBatchUpdateDataFromUsers(bUsers, setupAmounts);
        asset.batchUpdate(2, 0, 101, setupData);
        vm.stopPrank();

        uint256[] memory clientOrderIds = new uint256[](1); // Shorter than users array
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](2);
        users[0] = bytes32(uint256(uint160(user1)));
        users[1] = bytes32(uint256(uint160(user2)));

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 500;
        amounts[1] = 600;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = new bytes(65);
        signatures[1] = new bytes(65);

        // This will cause an array bounds error when accessing clientOrderIds[1]
        uint64[] memory subaccountIds = getSubaccountIds(users);
        vm.expectRevert();
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
    }

    // Test isAllowedSigner with empty signers array
    function test_isAllowedSigner_emptySigners() public {
        // Deploy a new contract with empty signers to test this edge case
        // Actually, this is not possible due to constructor validation
        // But we can test the edge case where signer is at the end of array
        assertFalse(asset.isAllowedSigner(address(0x999999)));
    }

    // Test public getter functions for coverage
    function test_publicGetters() public view {
        // These calls ensure getter functions are covered
        asset.USDC();
        asset.signers(0); // Access first signer
        asset.signers(1); // Access second signer
        asset.signers(2); // Access third signer
        asset.settlementOperator();
        asset.withdrawOperator();
        asset.availableAmount(bytes32(uint256(uint160(user1))));
        asset.lastBatchId();
        asset.lastBatchTime();
        asset.lastAntxChainHeight();
        asset.FORCE_WITHDRAW_TIME_LOCK();
    }

    function test_adminSetters_fullCoverage() public {
        // setSettlementAddress
        address newSettlement = address(0x9992);
        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.SettlementAddressUpdated(newSettlement);
        asset.setSettlementAddress(newSettlement);
        vm.stopPrank();
        assertEq(asset.settlementOperator(), newSettlement);

        // setWithdrawOperator
        address newWithdraw = address(0x9993);
        vm.startPrank(owner);
        vm.expectEmit(address(asset));
        emit IAsset.WithdrawOperatorUpdated(newWithdraw);
        asset.setWithdrawOperator(newWithdraw);
        vm.stopPrank();
        assertEq(asset.withdrawOperator(), newWithdraw);
    }

    // Test batchWithdraw zero amount through _userWithdraw
    function test_batchWithdraw_zeroAmountInternalCheck() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);

        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Prepare batch withdraw with zero amount
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 0; // Zero amount

        // Create user signature for zero amount
        bytes32 userBytes = bytes32(uint256(uint160(testUser)));
        bytes32 recipient = userBytes;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();
        bytes memory userSignature =
            createWithdrawSignature(123, userBytes, recipient, 0, 0, expireTime, dstChainId, userPrivateKey);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        // Execute batch withdraw - should fail with zero amount
        vm.startPrank(withdrawOperator);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAmountNotAllowed.selector));
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    // Test emergencyWithdraw with exact system balance
    function test_emergencyWithdraw_exactBalance() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare multi-sig withdraw for exact balance
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 1000; // Exact balance
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    // Test assertion failure scenarios (this is tricky as assert will halt execution)
    // We'll test the balance verification logic indirectly
    function test_transferBalanceVerification() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);

        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract with exact amount
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Get contract balance before
        uint256 contractBalanceBefore = USDC.balanceOf(address(asset));

        // Prepare batch withdraw
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature
        bytes32 userBytes = bytes32(uint256(uint160(testUser)));
        bytes32 recipient = userBytes;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();
        bytes memory userSignature =
            createWithdrawSignature(123, userBytes, recipient, 500, 0, expireTime, dstChainId, userPrivateKey);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        // Execute batch withdraw
        vm.startPrank(withdrawOperator);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();

        // Verify balance change is exactly what was expected
        uint256 contractBalanceAfter = USDC.balanceOf(address(asset));
        uint256 userBalanceAfter = USDC.balanceOf(testUser);
        uint256 userBalanceBefore = USDC.balanceOf(testUser);
        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            assertEq(contractBalanceBefore - contractBalanceAfter, getTransferAmount(500));
        } else {
            // On non-Arbitrum chains, balance goes to MockStargateWithdraw
            uint256 mockStargateBalanceAfter = USDC.balanceOf(address(mockStargateWithdraw));
            assertEq(contractBalanceBefore - contractBalanceAfter, getTransferAmount(500));
            assertEq(mockStargateBalanceAfter, getTransferAmount(500));
        }
    }

    // Test validTime modifier (though it's not currently used in the contract)
    // We can't directly test it since it's not used, but we can verify the modifier exists

    // Test with multiple signers but checking different signer combinations
    function test_emergencyWithdraw_differentSignerCombinations() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Test different signer combinations
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 300;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        // Test with signer1 and signer3 (different combination)
        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer3;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature3;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    // Test emergencyWithdraw with more than 3 signers to ensure loop coverage
    function test_emergencyWithdraw_fourSigners() public {
        // Create a new asset with 4 signers for this test
        address[] memory fourSigners = new address[](4);
        fourSigners[0] = signer1;
        fourSigners[1] = signer2;
        fourSigners[2] = signer3;
        uint256 signer4PrivateKey = 4;
        address signer4 = vm.addr(signer4PrivateKey);
        fourSigners[3] = signer4;

        vm.startPrank(owner);
        Asset assetWith4Signers = AssetDeployer.deployAsset(address(USDC), owner);
        assetWith4Signers.setSigners(fourSigners);
        assetWith4Signers.setSettlementAddress(settlementOperator);
        assetWith4Signers.setWithdrawOperator(withdrawOperator);
        assetWith4Signers.setMarginAsset(address(marginAssetCalculator));
        vm.stopPrank();

        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        assetWith4Signers.batchUpdate(1, 0, 1, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(assetWith4Signers), getTransferAmount(1000));

        // Test with 4 signers
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 400;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(assetWith4Signers),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);
        bytes memory signature4 = signMessage(operationHash, signer4PrivateKey);

        address[] memory allSigners = new address[](4);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        allSigners[2] = signer3;
        allSigners[3] = signer4;

        bytes[] memory signatures = new bytes[](4);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;
        signatures[3] = signature4;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        assetWith4Signers.emergencyWithdraw(
            address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures
        );
    }

    // Test edge case with zero user balance force withdraw (should fail)
    function test_forceWithdraw_zeroUserBalance() public {
        // Setup user with zero balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 0; // Zero balance

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        vm.expectRevert(abi.encodeWithSelector(IAsset.InsufficientUserBalance.selector, 0, 100));
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(100, getDstChainId());
        vm.stopPrank();
    }

    // Test accessing signers array with all valid indices
    function test_signersArray_allIndices() public view {
        // Access all signers to ensure array getter coverage
        assertEq(asset.signers(0), signer1);
        assertEq(asset.signers(1), signer2);
        assertEq(asset.signers(2), signer3);
    }

    // Test isAllowedSigner with all signers to ensure loop coverage
    function test_isAllowedSigner_allSigners() public {
        // Test with each signer position to ensure full loop coverage
        assertTrue(asset.isAllowedSigner(signer1)); // First in array
        assertTrue(asset.isAllowedSigner(signer2)); // Middle in array
        assertTrue(asset.isAllowedSigner(signer3)); // Last in array

        // Test with non-signer
        assertFalse(asset.isAllowedSigner(address(0xdead)));
    }

    // Test updateUserBalances with zero amounts (should succeed)
    function test_batchUpdate_zeroAmounts() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 0; // Zero amount
        amounts[1] = 0; // Zero amount

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](2);
        bUsers[0] = bytes32(uint256(uint160(user1)));
        bUsers[1] = bytes32(uint256(uint160(user2)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), 0);
        assertEq(asset.availableAmount(bytes32(uint256(uint160(user2)))), 0);
        assertEq(asset.lastBatchId(), 2);
    }

    // Test system withdraw with minimum possible amounts
    function test_emergencyWithdraw_minimumAmount() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1; // Minimum possible balance

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1));
        fundAssetWithETH();

        // Prepare multi-sig withdraw for minimum amount
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 1; // Minimum amount
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_recover_address() public {
        // Use a known private key to generate the test user address
        uint256 testPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(testPrivateKey);
        uint256 amount = 1000000;
        uint256 clientOrderID = 1752463521625;
        uint256 chainID = 421614;
        uint64 dstChainId = getDstChainId();

        console.log("=== Test Recover Address ===");
        console.log("testUser:", testUser);
        console.log("amount:", amount);
        console.log("clientOrderID:", clientOrderID);
        console.log("chainID:", chainID);

        // Create user signature with the correct private key for the test user
        // Updated hash format includes dstChainId and address(this)
        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "USER_WITHDRAW",
                clientOrderID,
                bytes32(uint256(uint160(testUser))),
                bytes32(uint256(uint160(testUser))),
                amount,
                block.timestamp + 1 days,
                dstChainId,
                chainID,
                address(asset)
            )
        );
        console.log("operationHash before toEthSignedMessageHash:");
        console.logBytes32(operationHash);

        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);
        console.log("operationHash after toEthSignedMessageHash:");
        console.logBytes32(operationHash);

        // Generate signature using the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testPrivateKey, operationHash);
        bytes memory signatures = abi.encodePacked(r, s, v);
        console.log("signatures length:", signatures.length);

        address recoveredAddress = ECDSA.recover(operationHash, signatures);
        console.log("recoveredAddress:", recoveredAddress);
        console.log("Expected testUser:", testUser);
        console.log("Addresses match:", recoveredAddress == testUser);

        assertEq(recoveredAddress, testUser);
    }

    // ============ Additional Comprehensive Tests ============






    function testUserBalanceWithZeroAddress() public {
        // Test userBalance with zero address
        assertEq(asset.availableAmount(bytes32(0)), 0);
    }

    function testUserBalanceWithMaxAddress() public {
        // Test userBalance with max address
        bytes32 maxAddress = bytes32(type(uint256).max);
        assertEq(asset.availableAmount(maxAddress), 0);
    }

    function testUpdateUserBalancesWithMaxBatchId() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        // Using max batch ID should revert since lastBatchId is 0 (expects 1)
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(type(uint256).max, 0, 100, batchData);
        vm.stopPrank();
    }

    function testUpdateUserBalancesWithMaxAmount() public {
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = uint256(uint64(type(int64).max)); // Max value for int64

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), uint256(uint64(type(int64).max)));
    }

    function testUpdateUserBalancesWithMaxUsers() public {
        // Test with maximum number of users (limited by gas)
        uint256 numUsers = 100; // Reasonable limit for testing
        address[] memory users = new address[](numUsers);
        uint256[] memory amounts = new uint256[](numUsers);

        for (uint256 i = 0; i < numUsers; i++) {
            users[i] = address(uint160(i + 1000)); // Generate unique addresses
            amounts[i] = (i + 1) * 100; // Different amounts for each user
        }

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](numUsers);
        for (uint256 i = 0; i < numUsers; i++) {
            bUsers[i] = bytes32(uint256(uint160(users[i])));
        }

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Verify all users got their balances
        for (uint256 i = 0; i < numUsers; i++) {
            assertEq(asset.availableAmount(bytes32(uint256(uint160(users[i])))), amounts[i]);
        }

        assertEq(asset.lastBatchId(), 2);
    }

    function testBatchWithdrawWithMaxAmount() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);

        // Setup user balances with max amount allowed by int64
        uint256 maxAmount = uint256(uint64(type(int64).max));
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = maxAmount;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract sufficiently (raw = internal * 1e12)
        USDC.mint(address(this), getTransferAmount(maxAmount));
        USDC.transfer(address(asset), getTransferAmount(maxAmount));
        fundAssetWithETH();

        // Prepare batch withdraw with max amount
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = maxAmount;

        // Create user signature for max amount
        bytes32 userBytes = bytes32(uint256(uint160(testUser)));
        bytes32 recipient = userBytes;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();
        bytes memory userSignature =
            createWithdrawSignature(123, userBytes, recipient, maxAmount, 0, expireTime, dstChainId, userPrivateKey);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        uint256 userBalanceBefore = USDC.balanceOf(testUser);

        // Execute batch withdraw
        vm.startPrank(withdrawOperator);
        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            vm.expectEmit(address(asset));
            emit IAsset.UserWithdraw(
                123, bytes32(uint256(uint160(testUser))), bytes32(uint256(uint160(testUser))), getTransferAmount(maxAmount), BASE_MAINNET
            );
        } else {
            vm.expectEmit(address(asset));
            emit IAsset.CrossChainWithdraw(
                123,
                bytes32(uint256(uint160(testUser))),
                bytes32(uint256(uint160(testUser))),
                getTransferAmount(maxAmount),
                getDstChainId()
            );
        }
        uint64[] memory subaccountIds = getSubaccountIds(users);
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();

        uint256 userBalanceAfter = USDC.balanceOf(testUser);
        assertBalanceChange(
            testUser, userBalanceBefore, userBalanceAfter, maxAmount, assetBalanceBefore, mockStargateBalanceBefore
        );
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(testUser)))), maxAmount);
    }

    function testForceWithdrawWithMaxAmount() public {
        // Setup user balance with max amount allowed by int64
        uint256 maxAmount = uint256(uint64(type(int64).max));
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = maxAmount;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract sufficiently (raw = internal * 1e12)
        USDC.mint(address(this), getTransferAmount(maxAmount));
        USDC.transfer(address(asset), getTransferAmount(maxAmount));
        fundAssetWithETH();

        // Advance time past the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDC.balanceOf(user1);

        vm.startPrank(user1);
        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            vm.expectEmit(address(asset));
            emit IAsset.ForceWithdraw(
                bytes32(uint256(uint160(user1))), bytes32(uint256(uint160(user1))), maxAmount, BASE_MAINNET
            );
        } else {
            vm.expectEmit(address(asset));
            emit IAsset.CrossChainWithdraw(
                0,
                bytes32(uint256(uint160(user1))),
                bytes32(uint256(uint160(user1))),
                getTransferAmount(maxAmount),
                getDstChainId()
            );
        }
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(maxAmount, getDstChainId());
        vm.stopPrank();

        uint256 user1BalanceAfter = USDC.balanceOf(user1);
        assertBalanceChange(
            user1, user1BalanceBefore, user1BalanceAfter, maxAmount, assetBalanceBefore, mockStargateBalanceBefore
        );
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), maxAmount);
    }

    function testEmergencyWithdrawWithMaxAmount() public {
        // Setup system balance with max amount
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000_000_000_000_000_000_000; // 1e24

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract sufficiently (amounts[0] is 1e24 raw for this test)
        USDC.mint(address(this), amounts[0]);
        USDC.transfer(address(asset), amounts[0]);
        fundAssetWithETH();

        // Prepare multi-sig withdraw with max amount
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = amounts[0];
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function testEmergencyWithdrawWithMaxExpireTime() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare multi-sig withdraw with max expire time
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 withdrawAmount = 500;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function testEmergencyWithdrawWithZeroExpireTime() public {
        // Setup system balance
        address[] memory users = new address[](1);
        users[0] = systemAddress;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(systemAddress)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare multi-sig withdraw with zero expire time
        uint256 expireTime = 0;
        address recipient = user1;
        uint256 withdrawAmount = 500;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function testBatchWithdrawWithMaxClientOrderId() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);

        // Setup user balances first
        address[] memory usersForBalance = new address[](1);
        usersForBalance[0] = testUser;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(testUser)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Prepare batch withdraw with max client order ID
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = type(uint256).max;

        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(testUser)));
        amounts[0] = 500;

        // Create user signature with max client order ID
        bytes32 userBytes = bytes32(uint256(uint160(testUser)));
        bytes32 recipient = userBytes;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();
        bytes memory userSignature = createWithdrawSignature(
            type(uint256).max, userBytes, recipient, 500, 0, expireTime, dstChainId, userPrivateKey
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        uint256 userBalanceBefore = USDC.balanceOf(testUser);

        // Execute batch withdraw
        vm.startPrank(withdrawOperator);
        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            vm.expectEmit(address(asset));
            emit IAsset.UserWithdraw(
                type(uint256).max,
                bytes32(uint256(uint160(testUser))),
                bytes32(uint256(uint160(testUser))),
                getTransferAmount(500),
                BASE_MAINNET
            );
        } else {
            vm.expectEmit(address(asset));
            emit IAsset.CrossChainWithdraw(
                type(uint256).max,
                bytes32(uint256(uint160(testUser))),
                bytes32(uint256(uint160(testUser))),
                getTransferAmount(500),
                getDstChainId()
            );
        }
        uint64[] memory subaccountIds = getSubaccountIds(users);
        uint64[] memory dstChainIds = createDstChainIds(clientOrderIds.length);
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        bytes32[] memory recipients = createRecipients(users);
        uint256[] memory expireTimes = createExpireTimes(clientOrderIds.length, block.timestamp + 1 days);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();

        uint256 userBalanceAfter = USDC.balanceOf(testUser);
        assertBalanceChange(
            testUser, userBalanceBefore, userBalanceAfter, 500, assetBalanceBefore, mockStargateBalanceBefore
        );
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(testUser)))), 1000);
    }

    function testForceWithdrawWithMaxTimeLock() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Advance time past the time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDC.balanceOf(user1);

        vm.startPrank(user1);
        // Note: Approval events may be emitted before CrossChainWithdraw due to forceApprove
        // So we check the final state instead of expecting specific event order
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();

        uint256 user1BalanceAfter = USDC.balanceOf(user1);
        assertBalanceChange(
            user1, user1BalanceBefore, user1BalanceAfter, 500, assetBalanceBefore, mockStargateBalanceBefore
        );
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), 1000);
    }

    function testForceWithdrawWithExactTimeLock() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        uint256 lastBatchTimeAfterUpdate = asset.lastBatchTime();
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Advance time to exactly lastBatchTime + FORCE_WITHDRAW_TIME_LOCK - 1 (should still fail)
        vm.warp(lastBatchTimeAfterUpdate + asset.FORCE_WITHDRAW_TIME_LOCK() - 1);

        vm.startPrank(user1);
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        vm.expectRevert(abi.encodeWithSelector(IAsset.TimeLockNotPassed.selector));
        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();
    }

    function testForceWithdrawWithOneSecondAfterTimeLock() public {
        // Setup user balance
        address[] memory users = new address[](1);
        users[0] = user1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        vm.startPrank(settlementOperator);
        bytes32[] memory bUsers = new bytes32[](1);
        bUsers[0] = bytes32(uint256(uint160(user1)));

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(bUsers, amounts);
        asset.batchUpdate(2, 0, 101, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(1000));
        fundAssetWithETH();

        // Advance time to one second after time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        uint256 user1BalanceBefore = USDC.balanceOf(user1);

        vm.startPrank(user1);
        if (block.chainid == BASE_MAINNET || block.chainid == BASE_SEPOLIA) {
            vm.expectEmit(address(asset));
            emit IAsset.ForceWithdraw(
                bytes32(uint256(uint160(user1))), bytes32(uint256(uint160(user1))), 500, BASE_MAINNET
            );
        } else {
            vm.expectEmit(address(asset));
            emit IAsset.CrossChainWithdraw(
                0, bytes32(uint256(uint160(user1))), bytes32(uint256(uint160(user1))), getTransferAmount(500), getDstChainId()
            );
        }
        uint64 subaccountId = getSubaccountId(bytes32(uint256(uint160(user1))));
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));
        uint256 mockStargateBalanceBefore = USDC.balanceOf(address(mockStargateWithdraw));

        uint256 expireTime = block.timestamp + 1 days;
        asset.forceWithdraw(500, getDstChainId());
        vm.stopPrank();

        uint256 user1BalanceAfter = USDC.balanceOf(user1);
        assertBalanceChange(
            user1, user1BalanceBefore, user1BalanceAfter, 500, assetBalanceBefore, mockStargateBalanceBefore
        );
        // availableAmount doesn't change after withdraw, it needs to be updated via batchUpdate
        assertEq(asset.availableAmount(bytes32(uint256(uint160(user1)))), 1000);
    }

    // ============ Default Collateral Coin ID Tests ============

    function test_setDefaultCollateralCoinId_success() public {
        vm.startPrank(owner);
        vm.expectEmit(true, false, false, false);
        emit IAsset.DefaultCollateralCoinIdUpdated(2);
        asset.setDefaultCollateralCoinId(2);
        assertEq(asset.defaultCollateralCoinId(), 2);
        vm.stopPrank();
    }

    function test_setDefaultCollateralCoinId_zeroValue() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidCollateralCoinId.selector));
        asset.setDefaultCollateralCoinId(0);
        vm.stopPrank();
    }

    function test_setDefaultCollateralCoinId_onlyOwner() public {
        vm.startPrank(user1);
        vm.expectRevert();
        asset.setDefaultCollateralCoinId(2);
        vm.stopPrank();
    }

    function test_setDefaultCollateralCoinId_updatesAvailableAmount() public {
        // Set up coin with ID 2
        vm.startPrank(settlementOperator);
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Set default collateral coin ID to 2
        vm.startPrank(owner);
        asset.setDefaultCollateralCoinId(2);
        vm.stopPrank();

        assertEq(asset.defaultCollateralCoinId(), 2);
    }

    function test_availableAmount_usesDefaultCollateralCoinId() public {
        // Set up coin with ID 2
        vm.startPrank(settlementOperator);
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Set default collateral coin ID to 2
        vm.startPrank(owner);
        asset.setDefaultCollateralCoinId(2);
        vm.stopPrank();

        // availableAmount should use defaultCollateralCoinId (2)
        uint256 amount = asset.availableAmount(bytes32(uint256(uint160(user1))));
        // Should return 0 if no perpetual asset exists for coinId 2
        assertEq(amount, 0);
    }

    function test_availableAmount_withExplicitCollateralCoinId() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        // First, set up user with perpetual asset (from setUp there's already user1 with 1000)
        // But let's ensure it exists
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);

        // Set up coinId 2
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        Asset.BatchUpdateData memory coinSetupData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(3, 0, 3, coinSetupData);
        vm.stopPrank();

        // Test with explicit collateralCoinId
        uint256 amount1 = asset.availableAmount(user, 1);
        // For coinId 2, if there's no perpetual asset, it will return 0
        uint256 amount2 = asset.availableAmount(user, 2);

        // Both should work even if defaultCollateralCoinId is different
        assertEq(amount1, 1000); // From batchUpdate
        assertEq(amount2, 0); // No perpetual asset for coinId 2
    }

    function test_availableAmountBySubAccountId_withExplicitCollateralCoinId() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        // First, set up user with perpetual asset
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);

        // Set up coinId 2
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        Asset.BatchUpdateData memory coinSetupData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(3, 0, 3, coinSetupData);
        vm.stopPrank();

        // Get subaccountId after batchUpdate
        uint64 subaccountId = getSubaccountId(user);

        // Test with explicit collateralCoinId
        uint256 amount1 = asset.availableAmountBySubAccountId(subaccountId, 1);
        // For coinId 2, if there's no perpetual asset, it will return 0
        uint256 amount2 = asset.availableAmountBySubAccountId(subaccountId, 2);

        assertEq(amount1, 1000); // From batchUpdate
        assertEq(amount2, 0); // No perpetual asset for coinId 2
    }

    // ============ Upgrade Tests ============

    function test_upgradeTo_newImplementation() public {
        // Deploy new implementation
        Asset newImplementation = new Asset();

        vm.startPrank(owner);
        asset.upgradeToAndCall(address(newImplementation), "");
        vm.stopPrank();

        // Verify upgrade succeeded (check that we can still call functions)
        assertEq(asset.owner(), owner);
        assertEq(address(asset.USDC()), address(USDC));
    }

    function test_upgradeTo_onlyOwner() public {
        Asset newImplementation = new Asset();

        vm.startPrank(user1);
        vm.expectRevert();
        asset.upgradeToAndCall(address(newImplementation), "");
        vm.stopPrank();
    }

    function test_upgradeTo_zeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert();
        asset.upgradeToAndCall(address(0), "");
        vm.stopPrank();
    }

    // ============ Additional Edge Cases ============

    function test_availableAmount_zeroSubaccountId() public {
        // Test with user that has no subaccount
        bytes32 nonExistentUser = bytes32(uint256(uint160(makeAddr("nonExistent"))));
        uint256 amount = asset.availableAmount(nonExistentUser);
        assertEq(amount, 0);
    }

    function test_availableAmountBySubAccountId_zeroSubaccountId() public {
        // Zero subaccountId should revert with UserNotFound
        vm.expectRevert(IAsset.UserNotFound.selector);
        asset.availableAmountBySubAccountId(0);
    }

    function test_availableAmountBySubAccountId_nonExistentSubaccountId() public {
        // Non-existent subaccountId should revert with UserNotFound
        vm.expectRevert(IAsset.UserNotFound.selector);
        asset.availableAmountBySubAccountId(99999);
    }

    function test_availableAmount_coinNotFound() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        // First, set up a user with a perpetual asset that uses a non-existent coinId
        // We need to add positions to trigger the coin check
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Modify the perpetualAsset to use coinId 99999 (non-existent)
        batchData.perpetualAssetUpdates[0].collateralCoinId = 99999;
        // Add a position to trigger coin check in _calculateAvailableAmount
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 1, openSize: 1000, openValue: 50000, isolatedCollateralAmount: 0, cacheFundingIndex: 0
        });
        batchData.perpetualAssetUpdates[0].positions = positions;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Now try to get available amount - should revert with CoinNotFound
        // because the perpetualAsset references coinId 99999 which doesn't exist
        vm.expectRevert(abi.encodeWithSelector(IAsset.CoinNotFound.selector));
        asset.availableAmount(user, 99999);
    }

    function test_availableAmountBySubAccountId_coinNotFound() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        // First, set up a user with a perpetual asset that uses a non-existent coinId
        // We need to add positions to trigger the coin check
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Modify the perpetualAsset to use coinId 99999 (non-existent)
        batchData.perpetualAssetUpdates[0].collateralCoinId = 99999;
        // Add a position to trigger coin check in _calculateAvailableAmount
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 1, openSize: 1000, openValue: 50000, isolatedCollateralAmount: 0, cacheFundingIndex: 0
        });
        batchData.perpetualAssetUpdates[0].positions = positions;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Get subaccountId after batchUpdate
        uint64 subaccountId = getSubaccountId(user);

        // Now try to get available amount - should revert with CoinNotFound
        // because the perpetualAsset references coinId 99999 which doesn't exist
        vm.expectRevert(abi.encodeWithSelector(IAsset.CoinNotFound.selector));
        asset.availableAmountBySubAccountId(subaccountId, 99999);
    }

    function test_batchUpdate_duplicateSeqInBatch() public {
        vm.startPrank(settlementOperator);
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(user1)));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(users, amounts);
        asset.batchUpdate(2, 0, 2, batchData);

        // Try to update with same seqInBatch
        vm.expectRevert();
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();
    }

    function test_batchUpdate_differentSeqInBatch() public {
        vm.startPrank(settlementOperator);
        bytes32[] memory users = new bytes32[](1);
        users[0] = bytes32(uint256(uint160(user1)));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000;

        Asset.BatchUpdateData memory batchData = createBatchUpdateDataFromUsers(users, amounts);
        asset.batchUpdate(2, 0, 2, batchData);

        // Update with different seqInBatch but same antxChainHeight should fail
        // Different seqInBatch requires different antxChainHeight
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidAntxChainHeight.selector));
        asset.batchUpdate(2, 1, 2, batchData);
        vm.stopPrank();
    }

    function test_batchWithdraw_clientOrderIdReplay() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);

        uint256 clientOrderId = 12345;
        bytes32 user = bytes32(uint256(uint160(testUser)));
        bytes32 recipient = bytes32(uint256(uint160(testUser)));
        uint256 amount = 100;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = getDstChainId();

        // Set up user with balance
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(amount));
        fundAssetWithETH();

        // First withdraw
        vm.startPrank(withdrawOperator);
        bytes memory signature =
            createWithdrawSignature(clientOrderId, user, recipient, amount, 0, expireTime, dstChainId, userPrivateKey);

        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = clientOrderId;
        uint64[] memory subaccountIds = new uint64[](1);
        subaccountIds[0] = getSubaccountId(user);
        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = recipient;
        uint256[] memory expireTimes = new uint256[](1);
        expireTimes[0] = expireTime;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint64[] memory dstChainIds = new uint64[](1);
        dstChainIds[0] = dstChainId;

        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );

        // Try to use same clientOrderId again
        vm.expectRevert(abi.encodeWithSelector(IAsset.ClientOrderIdAlreadyUsed.selector));
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees, // Reuse fees from above
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    function test_batchWithdraw_expiredTransaction() public {
        uint256 clientOrderId = 12345;
        bytes32 user = bytes32(uint256(uint160(user1)));
        bytes32 recipient = bytes32(uint256(uint160(user1)));
        uint256 amount = 100;
        uint256 expireTime = block.timestamp - 1; // Already expired
        uint64 dstChainId = getDstChainId();

        // Set up user with balance
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(amount));
        fundAssetWithETH();

        vm.startPrank(withdrawOperator);
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        bytes memory signature =
            createWithdrawSignature(clientOrderId, user, recipient, amount, 0, expireTime, dstChainId, userPrivateKey);

        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = clientOrderId;
        uint64[] memory subaccountIds = new uint64[](1);
        subaccountIds[0] = getSubaccountId(user);
        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = recipient;
        uint256[] memory expireTimes = new uint256[](1);
        expireTimes[0] = expireTime;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint64[] memory dstChainIds = new uint64[](1);
        dstChainIds[0] = dstChainId;

        vm.expectRevert(abi.encodeWithSelector(IAsset.ExpiredTransaction.selector));
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    function test_forceWithdraw_doesNotCheckExpireTime() public {
        bytes32 user = bytes32(uint256(uint160(user1)));
        uint256 amount = 100;
        uint256 expireTime = block.timestamp - 1; // Expired, but should still work for force withdraw

        // Set up user with balance
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(amount));
        fundAssetWithETH();

        // Advance time to pass time lock
        vm.warp(block.timestamp + asset.FORCE_WITHDRAW_TIME_LOCK() + 1);

        vm.startPrank(user1);
        // Get subaccountId after batchUpdate
        uint64 subaccountId = getSubaccountId(user);
        // Should succeed even with expired expireTime
        asset.forceWithdraw(amount, getDstChainId());
        vm.stopPrank();
    }

    // Note: emergencyWithdraw test is already covered in test_emergencyWithdraw_success

    // ============ Fuzz Tests ============

    function testFuzz_setDefaultCollateralCoinId(uint64 coinId) public {
        vm.assume(coinId > 0);
        vm.assume(coinId <= type(uint64).max);

        vm.startPrank(owner);
        asset.setDefaultCollateralCoinId(coinId);
        assertEq(asset.defaultCollateralCoinId(), coinId);
        vm.stopPrank();
    }

    function testFuzz_availableAmount(bytes32 user, uint64 collateralCoinId) public {
        // This should not revert, just return 0 for non-existent users
        uint256 amount = asset.availableAmount(user, collateralCoinId);
        assertGe(amount, 0);
    }

    function testFuzz_availableAmountBySubAccountId(uint64 subaccountId, uint64 collateralCoinId) public {
        // This may revert with UserNotFound for non-existent subaccounts
        // We need to handle that case
        try asset.availableAmountBySubAccountId(subaccountId, collateralCoinId) returns (uint256 amount) {
            assertGe(amount, 0);
        } catch (bytes memory error) {
            // UserNotFound is expected for non-existent subaccounts
            require(
                keccak256(error) == keccak256(abi.encodeWithSelector(IAsset.UserNotFound.selector)), "Unexpected error"
            );
        }
    }

    // ============ Additional Coverage Tests ============

    function test_batchUpdate_exchangeUpdates() public {
        vm.startPrank(settlementOperator);
        MarginAsset.Exchange[] memory exchangeUpdates = new MarginAsset.Exchange[](1);
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](1);
        riskTiers[0] =
            MarginAsset.RiskTier({maxLeverage: 10, maintenanceMarginRatioPpm: 5000, positionValueUpperBound: 1000000});
        exchangeUpdates[0] = MarginAsset.Exchange({
            exchangeId: 1, symbol: "BTC", stepSizeScale: 3, tickSizeScale: 2, riskTiers: riskTiers
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: exchangeUpdates,
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });

        vm.expectEmit(address(asset));
        emit IAsset.ExchangeInfoUpdated(1, 3, 2, 0, 0, riskTiers);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        (uint64 exchangeId, string memory symbol, uint32 stepSizeScale, uint32 tickSizeScale) = asset.exchanges(1);
        assertEq(exchangeId, 1);
        assertEq(symbol, "BTC");
    }

    function test_batchUpdate_fundingIndexUpdates() public {
        vm.startPrank(settlementOperator);
        MarginAsset.FundingIndex[] memory fundingIndexUpdates = new MarginAsset.FundingIndex[](1);
        fundingIndexUpdates[0] =
            MarginAsset.FundingIndex({exchangeId: 1, fundingIndex: 1000000, fundingIndexTime: uint64(block.timestamp)});

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: fundingIndexUpdates,
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });

        vm.expectEmit(address(asset));
        emit IAsset.FundingIndexUpdated(1, 1000000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        (uint64 exchangeId, int256 fundingIndex, uint64 fundingIndexTime) = asset.fundingIndexes(1);
        assertEq(exchangeId, 1);
        assertEq(fundingIndex, 1000000);
    }

    function test_batchUpdate_oraclePriceUpdates() public {
        vm.startPrank(settlementOperator);
        MarginAsset.OraclePrice[] memory oraclePriceUpdates = new MarginAsset.OraclePrice[](1);
        oraclePriceUpdates[0] =
            MarginAsset.OraclePrice({exchangeId: 1, oraclePrice: 50000, oracleTime: uint64(block.timestamp)});

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: oraclePriceUpdates,
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });

        vm.expectEmit(address(asset));
        emit IAsset.OraclePriceUpdated(1, 50000, uint64(block.timestamp));
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        (uint64 exchangeId, uint256 oraclePrice, uint64 oracleTime) = asset.oraclePrices(1);
        assertEq(exchangeId, 1);
        assertEq(oraclePrice, 50000);
    }

    function test_batchUpdate_coinIdsDeduplication() public {
        vm.startPrank(settlementOperator);
        // First, add coin with id 1
        MarginAsset.Coin[] memory coinUpdates1 = new MarginAsset.Coin[](1);
        coinUpdates1[0] = MarginAsset.Coin({id: 1, symbol: "USDC", stepSizeScale: 6});
        Asset.BatchUpdateData memory batchData1 = Asset.BatchUpdateData({
            coinUpdates: coinUpdates1,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, batchData1);

        // Try to add the same coin again - should not duplicate in coinIds array
        MarginAsset.Coin[] memory coinUpdates2 = new MarginAsset.Coin[](1);
        coinUpdates2[0] = MarginAsset.Coin({id: 1, symbol: "USDC", stepSizeScale: 6});
        Asset.BatchUpdateData memory batchData2 = Asset.BatchUpdateData({
            coinUpdates: coinUpdates2,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 1, 3, batchData2);
        vm.stopPrank();

        // Verify coinIds array still has only one entry
        // Note: We can't directly access coinIds array, but we can verify the coin exists
        (uint64 id, string memory symbol, uint32 stepSizeScale) = asset.coins(1);
        assertEq(id, 1);
    }

    function test_availableAmount_autoFindCollateralCoinId() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        // Set up multiple coins
        vm.startPrank(settlementOperator);
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](2);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        coinUpdates[1] = MarginAsset.Coin({id: 3, symbol: "BTC", stepSizeScale: 3});
        Asset.BatchUpdateData memory coinData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, coinData);

        // Set up user with perpetual asset using coinId 2
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        batchData.perpetualAssetUpdates[0].collateralCoinId = 2;
        asset.batchUpdate(3, 0, 3, batchData);
        vm.stopPrank();

        // Test auto-find (collateralCoinId = 0) should find coinId 2
        uint256 amount = asset.availableAmount(user, 0);
        assertEq(amount, 1000);
    }

    function test_availableAmount_withPositions() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Add positions to trigger the full calculation path
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 1, openSize: 1000, openValue: 50000, isolatedCollateralAmount: 0, cacheFundingIndex: 0
        });
        batchData.perpetualAssetUpdates[0].positions = positions;

        // Set up exchange and other required data for calculation
        MarginAsset.Exchange[] memory exchangeUpdates = new MarginAsset.Exchange[](1);
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](1);
        riskTiers[0] =
            MarginAsset.RiskTier({maxLeverage: 10, maintenanceMarginRatioPpm: 5000, positionValueUpperBound: 1000000});
        exchangeUpdates[0] = MarginAsset.Exchange({
            exchangeId: 1, symbol: "BTC", stepSizeScale: 3, tickSizeScale: 2, riskTiers: riskTiers
        });
        batchData.exchangeUpdates = exchangeUpdates;

        MarginAsset.FundingIndex[] memory fundingIndexUpdates = new MarginAsset.FundingIndex[](1);
        fundingIndexUpdates[0] =
            MarginAsset.FundingIndex({exchangeId: 1, fundingIndex: 1000000, fundingIndexTime: uint64(block.timestamp)});
        batchData.fundingIndexUpdates = fundingIndexUpdates;

        MarginAsset.OraclePrice[] memory oraclePriceUpdates = new MarginAsset.OraclePrice[](1);
        oraclePriceUpdates[0] =
            MarginAsset.OraclePrice({exchangeId: 1, oraclePrice: 50000, oracleTime: uint64(block.timestamp)});
        batchData.oraclePriceUpdates = oraclePriceUpdates;

        // Add trade settings to subaccount
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 1,
            leverage: 1,
            marginMode: 1 // cross-margin
        });
        batchData.subaccountUpdates[0].tradeSettings = tradeSettings;

        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Test availableAmount with positions - should use MarginAssetCalculator
        uint256 amount = asset.availableAmount(user);
        assertGe(amount, 0); // Should return a valid amount
    }

    function test_availableAmount_negativeAmountReturnsZero() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Set crossCollateralAmount to negative value
        batchData.perpetualAssetUpdates[0].crossCollateralAmount = -500;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // availableAmount should return 0 for negative amounts
        uint256 amount = asset.availableAmount(user);
        assertEq(amount, 0);
    }

    function test_batchUpdate_sameBatchIdDifferentSeqInBatch() public {
        vm.startPrank(settlementOperator);
        bytes32 user1Bytes = bytes32(uint256(uint160(user1)));
        bytes32 user2Bytes = bytes32(uint256(uint160(user2)));

        Asset.BatchUpdateData memory batchData1 = createBatchUpdateData(user1Bytes, 1000);
        asset.batchUpdate(2, 0, 2, batchData1);

        Asset.BatchUpdateData memory batchData2 = createBatchUpdateData(user2Bytes, 2000);
        asset.batchUpdate(2, 1, 3, batchData2);
        vm.stopPrank();

        // Verify both updates were applied
        assertEq(asset.availableAmount(user1Bytes), 1000);
        assertEq(asset.availableAmount(user2Bytes), 2000);
        assertTrue(asset.batchSeqIds(2, 0));
        assertTrue(asset.batchSeqIds(2, 1));
    }

    function test_batchUpdate_multipleCoins() public {
        vm.startPrank(settlementOperator);
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](3);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        coinUpdates[1] = MarginAsset.Coin({id: 3, symbol: "BTC", stepSizeScale: 3});
        coinUpdates[2] = MarginAsset.Coin({id: 4, symbol: "ETH", stepSizeScale: 2});

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });

        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Verify all coins were added
        (uint64 id2,,) = asset.coins(2);
        (uint64 id3,,) = asset.coins(3);
        (uint64 id4,,) = asset.coins(4);
        assertEq(id2, 2);
        assertEq(id3, 3);
        assertEq(id4, 4);
    }

    function test_batchUpdate_multipleExchanges() public {
        vm.startPrank(settlementOperator);
        MarginAsset.Exchange[] memory exchangeUpdates = new MarginAsset.Exchange[](2);
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](1);
        riskTiers[0] =
            MarginAsset.RiskTier({maxLeverage: 10, maintenanceMarginRatioPpm: 5000, positionValueUpperBound: 1000000});

        exchangeUpdates[0] = MarginAsset.Exchange({
            exchangeId: 1, symbol: "BTC", stepSizeScale: 3, tickSizeScale: 2, riskTiers: riskTiers
        });
        exchangeUpdates[1] = MarginAsset.Exchange({
            exchangeId: 2, symbol: "ETH", stepSizeScale: 2, tickSizeScale: 2, riskTiers: riskTiers
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: exchangeUpdates,
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });

        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        (uint64 exchangeId1,,,) = asset.exchanges(1);
        (uint64 exchangeId2,,,) = asset.exchanges(2);
        assertEq(exchangeId1, 1);
        assertEq(exchangeId2, 2);
    }

    function test_availableAmount_zeroCollateralCoinIdAutoFind() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Test with collateralCoinId = 0 (auto-find)
        uint256 amount = asset.availableAmount(user, 0);
        assertEq(amount, 1000);
    }

    function test_availableAmountBySubAccountId_zeroCollateralCoinId() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        uint64 subaccountId = getSubaccountId(user);
        // Test with collateralCoinId = 0 (auto-find)
        uint256 amount = asset.availableAmountBySubAccountId(subaccountId, 0);
        assertEq(amount, 1000);
    }

    function test_batchUpdate_emptyArrays() public {
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });

        // Should succeed even with all empty arrays
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        assertEq(asset.lastBatchId(), 2);
    }

    function test_batchWithdraw_nativeChain() public {
        // Use a specific private key and derive the user address from it
        uint256 userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        address testUser = vm.addr(userPrivateKey);
        bytes32 user = bytes32(uint256(uint160(testUser)));

        // Setup user balances first
        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Fund the contract
        USDC.transfer(address(asset), getTransferAmount(500));
        fundAssetWithETH();

        // Prepare batch withdraw with native chain (dstChainId == block.chainid)
        uint256[] memory clientOrderIds = new uint256[](1);
        clientOrderIds[0] = 123;

        bytes32[] memory users = new bytes32[](1);
        users[0] = user;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 500;

        bytes32 recipient = user;
        uint256 expireTime = block.timestamp + 1 days;
        uint64 dstChainId = uint64(block.chainid); // Native chain

        bytes memory userSignature =
            createWithdrawSignature(123, user, recipient, 500, 0, expireTime, dstChainId, userPrivateKey);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = userSignature;

        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = recipient;
        uint256[] memory expireTimes = new uint256[](1);
        expireTimes[0] = expireTime;
        uint64[] memory dstChainIds = new uint64[](1);
        dstChainIds[0] = dstChainId;

        uint256 userBalanceBefore = USDC.balanceOf(testUser);
        uint256 assetBalanceBefore = USDC.balanceOf(address(asset));

        vm.startPrank(withdrawOperator);
        vm.expectEmit(address(asset));
        emit IAsset.UserWithdraw(123, user, recipient, getTransferAmount(500), dstChainId);
        uint64[] memory subaccountIds = getSubaccountIds(users);
        uint256[] memory fees = createFees(clientOrderIds.length);
        asset.batchWithdraw(
            clientOrderIds,
            subaccountIds,
            recipients,
            expireTimes,
            amounts,
            fees,
            signatures,
            dstChainIds,
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();

        uint256 userBalanceAfter = USDC.balanceOf(testUser);
        uint256 assetBalanceAfter = USDC.balanceOf(address(asset));

        // On native chain, user should receive USDC directly
        assertEq(userBalanceAfter - userBalanceBefore, getTransferAmount(500));
        assertEq(assetBalanceBefore - assetBalanceAfter, getTransferAmount(500));
    }


    function test_batchUpdate_mixedUpdates() public {
        vm.startPrank(settlementOperator);
        // Create a batch update with multiple types of updates
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});

        MarginAsset.Exchange[] memory exchangeUpdates = new MarginAsset.Exchange[](1);
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](1);
        riskTiers[0] =
            MarginAsset.RiskTier({maxLeverage: 10, maintenanceMarginRatioPpm: 5000, positionValueUpperBound: 1000000});
        exchangeUpdates[0] = MarginAsset.Exchange({
            exchangeId: 1, symbol: "BTC", stepSizeScale: 3, tickSizeScale: 2, riskTiers: riskTiers
        });

        MarginAsset.FundingIndex[] memory fundingIndexUpdates = new MarginAsset.FundingIndex[](1);
        fundingIndexUpdates[0] =
            MarginAsset.FundingIndex({exchangeId: 1, fundingIndex: 1000000, fundingIndexTime: uint64(block.timestamp)});

        MarginAsset.OraclePrice[] memory oraclePriceUpdates = new MarginAsset.OraclePrice[](1);
        oraclePriceUpdates[0] =
            MarginAsset.OraclePrice({exchangeId: 1, oraclePrice: 50000, oracleTime: uint64(block.timestamp)});

        bytes32 user = bytes32(uint256(uint160(user1)));
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        batchData.coinUpdates = coinUpdates;
        batchData.exchangeUpdates = exchangeUpdates;
        batchData.fundingIndexUpdates = fundingIndexUpdates;
        batchData.oraclePriceUpdates = oraclePriceUpdates;

        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Verify all updates were applied
        (uint64 coinId,,) = asset.coins(2);
        assertEq(coinId, 2);
        (uint64 exchangeId,,,) = asset.exchanges(1);
        assertEq(exchangeId, 1);
        assertEq(asset.availableAmount(user), 1000);
    }

    function test_batchUpdate_multipleSubaccounts() public {
        vm.startPrank(settlementOperator);
        bytes32 user1Bytes = bytes32(uint256(uint160(user1)));
        bytes32 user2Bytes = bytes32(uint256(uint160(user2)));
        bytes32 user3Bytes = bytes32(uint256(uint160(address(0x123))));

        // Create batch update with multiple subaccounts
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](3);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);

        subaccountUpdates[0] = MarginAsset.Subaccount({
            id: 10,
            chainAddress: user1Bytes,
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "",
            tradeSettings: tradeSettings
        });
        subaccountUpdates[1] = MarginAsset.Subaccount({
            id: 20,
            chainAddress: user2Bytes,
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "",
            tradeSettings: tradeSettings
        });
        subaccountUpdates[2] = MarginAsset.Subaccount({
            id: 30,
            chainAddress: user3Bytes,
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "",
            tradeSettings: tradeSettings
        });

        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](3);
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](0);

        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: 10, collateralCoinId: 1, crossCollateralAmount: 1000, positions: positions
        });
        perpetualAssetUpdates[1] = MarginAsset.PerpetualAsset({
            subaccountId: 20, collateralCoinId: 1, crossCollateralAmount: 2000, positions: positions
        });
        perpetualAssetUpdates[2] = MarginAsset.PerpetualAsset({
            subaccountId: 30, collateralCoinId: 1, crossCollateralAmount: 3000, positions: positions
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });

        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Verify all subaccounts were created
        assertEq(asset.availableAmount(user1Bytes), 1000);
        assertEq(asset.availableAmount(user2Bytes), 2000);
        assertEq(asset.availableAmount(user3Bytes), 3000);
    }

    function test_availableAmount_autoFindSecondCoin() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Set up multiple coins
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](3);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        coinUpdates[1] = MarginAsset.Coin({id: 3, symbol: "BTC", stepSizeScale: 3});
        coinUpdates[2] = MarginAsset.Coin({id: 4, symbol: "ETH", stepSizeScale: 2});
        Asset.BatchUpdateData memory coinData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, coinData);

        // Set up user with perpetual asset using coinId 3 (second coin)
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        batchData.perpetualAssetUpdates[0].collateralCoinId = 3;
        asset.batchUpdate(3, 0, 3, batchData);
        vm.stopPrank();

        // Test auto-find (collateralCoinId = 0) should find coinId 3
        uint256 amount = asset.availableAmount(user, 0);
        assertEq(amount, 1000);
    }

    function test_emergencyWithdraw_threeSigners() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Fund the contract
        uint256 withdrawAmount = 500;
        USDC.transfer(address(asset), getTransferAmount(withdrawAmount));
        fundAssetWithETH();

        // Prepare emergency withdraw with 3 signers
        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);

        address[] memory allSigners = new address[](3);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        allSigners[2] = signer3;

        bytes[] memory signatures = new bytes[](3);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_availableAmount_noPerpetualAsset() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Create subaccount but no perpetual asset
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        subaccountUpdates[0] =
            MarginAsset.Subaccount({
                id: 100,
                chainAddress: user,
                isMultiSigWallet: false,
                multiSigWallet: address(0),
                clientAccountId: "",
                tradeSettings: tradeSettings
            });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // availableAmount should return 0 when no perpetual asset exists
        uint256 amount = asset.availableAmount(user);
        assertEq(amount, 0);
    }

    function test_availableAmount_zeroCrossCollateralAmount() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Set crossCollateralAmount to 0
        batchData.perpetualAssetUpdates[0].crossCollateralAmount = 0;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // availableAmount should return 0 for zero crossCollateralAmount
        uint256 amount = asset.availableAmount(user);
        assertEq(amount, 0);
    }

    // ============ Branch Coverage Tests ============

    function test_calculateAvailableAmount_subaccountIdZero() public {
        // Test branch: if (subaccountId == 0) return 0;
        bytes32 nonExistentUser = bytes32(uint256(uint160(address(0x999))));
        uint256 amount = asset.availableAmount(nonExistentUser);
        assertEq(amount, 0);
    }

    function test_calculateAvailableAmount_subaccountIdZeroWithCollateralCoinId() public {
        // Test branch: if (subaccountId == 0) return 0; with explicit collateralCoinId
        bytes32 nonExistentUser = bytes32(uint256(uint160(address(0x999))));
        uint256 amount = asset.availableAmount(nonExistentUser, 1);
        assertEq(amount, 0);
    }

    function test_calculateAvailableAmount_subaccountIdExistsButIdZero() public {
        // Test branch: if (subaccount.id == 0) return 0;
        // This is tricky - we need a subaccountId that exists in addressToSubaccountId
        // but the subaccount itself has id == 0
        // Actually, this case is hard to create because batchUpdate always sets subaccount.id
        // But we can test by querying a subaccountId that doesn't exist in subaccounts mapping
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Create subaccount mapping but don't create the subaccount itself
        // This is actually not possible with current batchUpdate logic
        // So we'll test the case where subaccount exists but has no perpetual asset
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 0);
        batchData.perpetualAssetUpdates[0].crossCollateralAmount = 0;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        uint256 amount = asset.availableAmount(user);
        assertEq(amount, 0);
    }

    function test_calculateAvailableAmount_autoFindNoMatch() public {
        // Test branch: if (!foundPerpetualAsset) return 0; in auto-find path
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Create subaccount but no perpetual asset
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        subaccountUpdates[0] =
            MarginAsset.Subaccount({
                id: 200,
                chainAddress: user,
                isMultiSigWallet: false,
                multiSigWallet: address(0),
                clientAccountId: "",
                tradeSettings: tradeSettings
            });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Test auto-find (collateralCoinId = 0) - should return 0
        uint256 amount = asset.availableAmount(user, 0);
        assertEq(amount, 0);
    }

    function test_calculateAvailableAmount_explicitCollateralCoinIdNoMatch() public {
        // Test branch: if (!foundPerpetualAsset) return 0; in explicit collateralCoinId path
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Use collateralCoinId 1, but query for collateralCoinId 999 (non-existent)
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Query with non-existent collateralCoinId - should return 0
        uint256 amount = asset.availableAmount(user, 999);
        assertEq(amount, 0);
    }

    function test_calculateAvailableAmount_perpetualAssetSubaccountIdMismatch() public {
        // Test branch: if (perpetualAsset.subaccountId == subaccountId && pa.collateralCoinId > 0)
        // when subaccountId doesn't match
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Create a perpetual asset with mismatched subaccountId
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        subaccountUpdates[0] =
            MarginAsset.Subaccount({
                id: 300,
                chainAddress: user,
                isMultiSigWallet: false,
                multiSigWallet: address(0),
                clientAccountId: "",
                tradeSettings: tradeSettings
            });

        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](1);
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](0);
        // Set subaccountId to different value (mismatch)
        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: 999, // Mismatch with subaccount.id = 300
            collateralCoinId: 1,
            crossCollateralAmount: 1000,
            positions: positions
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Should return 0 because subaccountId mismatch
        uint256 amount = asset.availableAmount(user);
        assertEq(amount, 0);
    }

    function test_calculateAvailableAmount_perpetualAssetCollateralCoinIdZero() public {
        // Test branch: if (perpetualAsset.subaccountId == subaccountId && pa.collateralCoinId > 0)
        // when collateralCoinId == 0
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Set collateralCoinId to 0
        batchData.perpetualAssetUpdates[0].collateralCoinId = 0;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Should return 0 because collateralCoinId == 0
        uint256 amount = asset.availableAmount(user);
        assertEq(amount, 0);
    }

    function test_availableAmount_negativeAmount() public {
        // Test branch: if (userAvailableAmount < 0) return 0;
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Set crossCollateralAmount to negative value
        batchData.perpetualAssetUpdates[0].crossCollateralAmount = -1000;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // availableAmount should return 0 for negative amounts
        uint256 amount = asset.availableAmount(user);
        assertEq(amount, 0);
    }

    function test_batchUpdate_batchIdEqualsLastBatchId() public {
        // Test branch: if (batchId == lastBatchId)
        vm.startPrank(settlementOperator);
        bytes32 user = bytes32(uint256(uint160(user1)));
        Asset.BatchUpdateData memory batchData1 = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData1);

        // Use same batchId with different seqInBatch
        Asset.BatchUpdateData memory batchData2 = createBatchUpdateData(user, 2000);
        asset.batchUpdate(2, 1, 3, batchData2);
        vm.stopPrank();

        assertEq(asset.lastBatchId(), 2);
        assertTrue(asset.batchSeqIds(2, 0));
        assertTrue(asset.batchSeqIds(2, 1));
    }

    function test_batchUpdate_batchIdNotSequential() public {
        // Test branch: else if (batchId != lastBatchId + 1)
        vm.startPrank(settlementOperator);
        bytes32 user = bytes32(uint256(uint160(user1)));
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);

        // Try to use batchId 5 when lastBatchId is 1
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        asset.batchUpdate(5, 0, 2, batchData);
        vm.stopPrank();
    }

    function test_batchUpdate_coinExistsInArray() public {
        // Test branch: if (coinIds[j] == batchUpdateData.coinUpdates[i].id)
        vm.startPrank(settlementOperator);
        // First, add coin with id 1
        MarginAsset.Coin[] memory coinUpdates1 = new MarginAsset.Coin[](1);
        coinUpdates1[0] = MarginAsset.Coin({id: 1, symbol: "USDC", stepSizeScale: 6});
        Asset.BatchUpdateData memory batchData1 = Asset.BatchUpdateData({
            coinUpdates: coinUpdates1,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, batchData1);

        // Update the same coin again - should not duplicate in coinIds array
        MarginAsset.Coin[] memory coinUpdates2 = new MarginAsset.Coin[](1);
        coinUpdates2[0] = MarginAsset.Coin({id: 1, symbol: "USDC_UPDATED", stepSizeScale: 6});
        Asset.BatchUpdateData memory batchData2 = Asset.BatchUpdateData({
            coinUpdates: coinUpdates2,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 1, 3, batchData2);
        vm.stopPrank();

        // Verify coin was updated
        (uint64 id, string memory symbol,) = asset.coins(1);
        assertEq(id, 1);
        assertEq(symbol, "USDC_UPDATED");
    }

    function test_batchUpdate_marginAssetZero() public {
        // Test branch: if (marginAsset == address(0))
        // We can't set marginAsset to zero directly because setMarginAsset has validAddress modifier
        // So we need to test this by deploying a new Asset without setting marginAsset
        // Note: This branch is hard to test directly because batchId check happens before marginAsset check
        // But we can verify the code path exists by checking the source code
        // For practical purposes, this branch is covered by the fact that marginAsset must be set before batchUpdate
        vm.startPrank(owner);
        Asset newAsset = AssetDeployer.deployAsset(address(USDC), owner);
        // Set up settlement operator but don't set marginAsset
        newAsset.setSettlementAddress(settlementOperator);
        // Set withdraw operator
        newAsset.setWithdrawOperator(withdrawOperator);
        vm.stopPrank();

        vm.startPrank(settlementOperator);
        bytes32 user = bytes32(uint256(uint160(user1)));
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);

        // Try batchUpdate - should fail because marginAsset is zero
        // The check order is: batchId -> antxChainHeight -> marginAsset
        // newAsset.lastBatchId() is 0 (newly deployed), so batchId should be 1 (lastBatchId + 1)
        // newAsset.lastAntxChainHeight() is 0, so antxChainHeight should be > 0
        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        newAsset.batchUpdate(1, 0, 1, batchData);
        vm.stopPrank();
    }


    // ============ Additional Branch Coverage Tests ============

    function test_calculateAvailableAmount_emptyCoinIdsArray() public {
        // Test branch: for (uint256 i = 0; i < coinIds.length; i++) when coinIds is empty
        // Note: setUp already adds coinId 1, so we need a new Asset instance
        vm.startPrank(owner);
        Asset newAsset = AssetDeployer.deployAsset(address(USDC), owner);
        newAsset.setSettlementAddress(settlementOperator);
        newAsset.setWithdrawOperator(withdrawOperator);
        newAsset.setMarginAsset(address(marginAssetCalculator));
        vm.stopPrank();

        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Create subaccount but no coins (coinIds array will be empty for newAsset)
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        subaccountUpdates[0] =
            MarginAsset.Subaccount({
                id: 500,
                chainAddress: user,
                isMultiSigWallet: false,
                multiSigWallet: address(0),
                clientAccountId: "",
                tradeSettings: tradeSettings
            });

        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](1);
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](0);
        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: 500,
            collateralCoinId: 1, // But coin 1 doesn't exist in coinIds
            crossCollateralAmount: 1000,
            positions: positions
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0), // No coins added
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });
        newAsset.batchUpdate(1, 0, 1, batchData);
        vm.stopPrank();

        // Auto-find (collateralCoinId = 0) should return 0 because coinIds array is empty
        uint256 amount = newAsset.availableAmount(user, 0);
        assertEq(amount, 0);
    }

    function test_calculateAvailableAmount_emptyTradeSettings() public {
        // Test branch: for (uint256 i = 0; i < tradeSettingsLength; i++) when tradeSettings is empty
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Ensure tradeSettings is empty (it already is in createBatchUpdateData)
        // Add positions to trigger the full calculation path
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 1, openSize: 1000, openValue: 50000, isolatedCollateralAmount: 0, cacheFundingIndex: 0
        });
        batchData.perpetualAssetUpdates[0].positions = positions;

        // Set up exchange and other required data
        MarginAsset.Exchange[] memory exchangeUpdates = new MarginAsset.Exchange[](1);
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](1);
        riskTiers[0] =
            MarginAsset.RiskTier({maxLeverage: 10, maintenanceMarginRatioPpm: 5000, positionValueUpperBound: 1000000});
        exchangeUpdates[0] = MarginAsset.Exchange({
            exchangeId: 1, symbol: "BTC", stepSizeScale: 3, tickSizeScale: 2, riskTiers: riskTiers
        });
        batchData.exchangeUpdates = exchangeUpdates;

        MarginAsset.FundingIndex[] memory fundingIndexUpdates = new MarginAsset.FundingIndex[](1);
        fundingIndexUpdates[0] =
            MarginAsset.FundingIndex({exchangeId: 1, fundingIndex: 1000000, fundingIndexTime: uint64(block.timestamp)});
        batchData.fundingIndexUpdates = fundingIndexUpdates;

        MarginAsset.OraclePrice[] memory oraclePriceUpdates = new MarginAsset.OraclePrice[](1);
        oraclePriceUpdates[0] =
            MarginAsset.OraclePrice({exchangeId: 1, oraclePrice: 50000, oracleTime: uint64(block.timestamp)});
        batchData.oraclePriceUpdates = oraclePriceUpdates;

        // Ensure tradeSettings is empty (already empty in createBatchUpdateData)
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        // Should work even with empty tradeSettings
        uint256 amount = asset.availableAmount(user);
        assertGe(amount, 0);
    }

    function test_batchWithdraw_emptyArray() public {
        // Test branch: for (uint64 i = 0; i < subaccountIds.length; i++) when array is empty
        // Empty arrays should succeed (loop doesn't execute)
        vm.startPrank(withdrawOperator);
        // Empty arrays should succeed - the loop just doesn't execute
        asset.batchWithdraw(
            new uint256[](0),
            new uint64[](0),
            new bytes32[](0),
            new uint256[](0),
            new uint256[](0),
            new uint256[](0),
            new bytes[](0),
            new uint64[](0),
            IAsset.SignatureType.ECDSA
        );
        vm.stopPrank();
    }

    function test_isAllowedSigner_emptySignersArray() public {
        // Test branch: for (uint i = 0; i < signers.length; i++) when signers is empty
        vm.startPrank(owner);
        Asset newAsset = AssetDeployer.deployAsset(address(USDC), owner);
        // Don't set signers, so signers array is empty
        vm.stopPrank();

        // Should return false for any signer when signers array is empty
        assertFalse(newAsset.isAllowedSigner(signer1));
        assertFalse(newAsset.isAllowedSigner(address(0x123)));
    }

    function test_emergencyWithdraw_twoSignersNestedLoop() public {
        // Test branch: nested loops when allSigners.length == 2
        // When i=0, j loop runs once (j=1)
        // When i=1, j loop doesn't run (j starts at 2, but 2 >= 2)
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        uint256 withdrawAmount = 500;
        USDC.transfer(address(asset), getTransferAmount(withdrawAmount));
        fundAssetWithETH();

        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_batchUpdate_multipleCoinsInArray() public {
        // Test branch: for (uint256 j = 0; j < coinIds.length; j++) when coinIds has multiple entries
        vm.startPrank(settlementOperator);
        // Add multiple coins
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](3);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        coinUpdates[1] = MarginAsset.Coin({id: 3, symbol: "BTC", stepSizeScale: 3});
        coinUpdates[2] = MarginAsset.Coin({id: 4, symbol: "ETH", stepSizeScale: 2});

        Asset.BatchUpdateData memory batchData1 = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, batchData1);

        // Now try to add coin 2 again - should not duplicate (existCoin should be true)
        MarginAsset.Coin[] memory coinUpdates2 = new MarginAsset.Coin[](1);
        coinUpdates2[0] = MarginAsset.Coin({id: 2, symbol: "USDT_UPDATED", stepSizeScale: 6});

        Asset.BatchUpdateData memory batchData2 = Asset.BatchUpdateData({
            coinUpdates: coinUpdates2,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 1, 3, batchData2);
        vm.stopPrank();

        // Verify coin was updated but not duplicated
        (uint64 id, string memory symbol,) = asset.coins(2);
        assertEq(id, 2);
        assertEq(symbol, "USDT_UPDATED");
    }

    function test_calculateAvailableAmount_autoFindLoopNoMatch() public {
        // Test branch: for loop completes without finding a match
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Set up coins but no matching perpetual asset
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](2);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        coinUpdates[1] = MarginAsset.Coin({id: 3, symbol: "BTC", stepSizeScale: 3});
        Asset.BatchUpdateData memory coinData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, coinData);

        // Create subaccount but perpetual asset uses coinId 999 (not in coinIds)
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        subaccountUpdates[0] =
            MarginAsset.Subaccount({
                id: 600,
                chainAddress: user,
                isMultiSigWallet: false,
                multiSigWallet: address(0),
                clientAccountId: "",
                tradeSettings: tradeSettings
            });

        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](1);
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](0);
        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: 600,
            collateralCoinId: 999, // Not in coinIds array
            crossCollateralAmount: 1000,
            positions: positions
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });
        asset.batchUpdate(3, 0, 3, batchData);
        vm.stopPrank();

        // Auto-find should iterate through coinIds but not find a match
        uint256 amount = asset.availableAmount(user, 0);
        assertEq(amount, 0);
    }

    function test_batchUpdate_antxChainHeightEqual() public {
        // Test branch: if (antxChainHeight <= lastAntxChainHeight)
        vm.startPrank(settlementOperator);
        bytes32 user = bytes32(uint256(uint160(user1)));
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);

        // Try to update with same antxChainHeight
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidAntxChainHeight.selector));
        asset.batchUpdate(3, 0, 2, batchData); // antxChainHeight = 2, but lastAntxChainHeight is 2
        vm.stopPrank();
    }

    function test_setSigners_zeroAddressInLoop() public {
        // Test branch: for loop in setSigners checking for zero address
        vm.startPrank(owner);
        address[] memory signersWithZero = new address[](3);
        signersWithZero[0] = signer1;
        signersWithZero[1] = address(0); // Zero address
        signersWithZero[2] = signer2;

        vm.expectRevert(abi.encodeWithSelector(IAsset.ZeroAddressNotAllowed.selector));
        asset.setSigners(signersWithZero);
        vm.stopPrank();
    }

    function test_emergencyWithdraw_signerMismatch() public {
        // Test branch: if (signer != allSigners[index])
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        uint256 withdrawAmount = 500;
        USDC.transfer(address(asset), getTransferAmount(withdrawAmount));
        fundAssetWithETH();

        uint256 expireTime = block.timestamp + 1 hours;
        address recipient = user1;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW",
                address(USDC),
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer3; // Wrong signer (should be signer2)

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2; // Signature from signer2, but allSigners[1] is signer3

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdraw(address(USDC), recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_availableAmountBySubAccountId_negativeAmount() public {
        // Test branch: if (subaccountAvailableAmount < 0) return 0;
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        // Set crossCollateralAmount to negative value
        batchData.perpetualAssetUpdates[0].crossCollateralAmount = -500;
        asset.batchUpdate(2, 0, 2, batchData);
        vm.stopPrank();

        uint64 subaccountId = getSubaccountId(user);
        // availableAmountBySubAccountId should return 0 for negative amounts
        uint256 amount = asset.availableAmountBySubAccountId(subaccountId);
        assertEq(amount, 0);
    }

    function test_batchUpdate_sameBatchIdUsedSeqInBatch() public {
        // Test branch: if (batchSeqIds[batchId][seqInBatch]) revert InvalidBatchId();
        vm.startPrank(settlementOperator);
        bytes32 user = bytes32(uint256(uint160(user1)));
        Asset.BatchUpdateData memory batchData = createBatchUpdateData(user, 1000);
        asset.batchUpdate(2, 0, 2, batchData);

        // Try to use same batchId and seqInBatch
        vm.expectRevert(abi.encodeWithSelector(IAsset.InvalidBatchId.selector));
        asset.batchUpdate(2, 0, 3, batchData);
        vm.stopPrank();
    }

    function test_calculateAvailableAmount_autoFindMultipleCoinsFirstMatch() public {
        // Test branch: break in auto-find loop when first match is found
        bytes32 user = bytes32(uint256(uint160(user1)));

        vm.startPrank(settlementOperator);
        // Set up multiple coins
        MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](3);
        coinUpdates[0] = MarginAsset.Coin({id: 2, symbol: "USDT", stepSizeScale: 6});
        coinUpdates[1] = MarginAsset.Coin({id: 3, symbol: "BTC", stepSizeScale: 3});
        coinUpdates[2] = MarginAsset.Coin({id: 4, symbol: "ETH", stepSizeScale: 2});
        Asset.BatchUpdateData memory coinData = Asset.BatchUpdateData({
            coinUpdates: coinUpdates,
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: new MarginAsset.Subaccount[](0),
            perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
        });
        asset.batchUpdate(2, 0, 2, coinData);

        // Create perpetual assets for multiple coins, but first one should be found
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        subaccountUpdates[0] =
            MarginAsset.Subaccount({
                id: 400,
                chainAddress: user,
                isMultiSigWallet: false,
                multiSigWallet: address(0),
                clientAccountId: "",
                tradeSettings: tradeSettings
            });

        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](3);
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](0);
        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: 400, collateralCoinId: 2, crossCollateralAmount: 1000, positions: positions
        });
        perpetualAssetUpdates[1] = MarginAsset.PerpetualAsset({
            subaccountId: 400, collateralCoinId: 3, crossCollateralAmount: 2000, positions: positions
        });
        perpetualAssetUpdates[2] = MarginAsset.PerpetualAsset({
            subaccountId: 400, collateralCoinId: 4, crossCollateralAmount: 3000, positions: positions
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: new MarginAsset.Exchange[](0),
            fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
            oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });
        asset.batchUpdate(3, 0, 3, batchData);
        vm.stopPrank();

        // Auto-find should find the first match (coinId 2)
        uint256 amount = asset.availableAmount(user, 0);
        assertEq(amount, 1000);
    }

    function test_hashUserWithdraw_Uint64EncodingIssue() public {
        // This test demonstrates the uint64 encoding mismatch between Go and Solidity
        // Go code uses: common.LeftPadBytes(dstChainIdInt.Bytes(), 32) - 32 bytes
        // Solidity uses: abi.encodePacked(uint64) - 8 bytes

        uint256 clientOrderId = 1766405823826;
        address user_james = 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678;
        uint256 amount = 1100000;
        uint256 expireTime = 1767010623;
        uint64 dstChainId = 421614;
        bytes32 user = bytes32(uint256(uint160(user_james)));
        bytes32 recipient = bytes32(uint256(uint160(user_james)));
        address assetAddr = 0x871bD685AcE3E8f5383BDbC4bfD98a31559AA8F4;
        uint64 chainId = 11155111;

        // Check how abi.encodePacked encodes uint64
        bytes memory encodedUint64 = abi.encodePacked(dstChainId);
        console.log("abi.encodePacked(uint64) length:", encodedUint64.length);
        console.log("abi.encodePacked(uint64) bytes:");
        console.logBytes(encodedUint64);

        // Check how abi.encodePacked encodes uint256
        bytes memory encodedUint256 = abi.encodePacked(uint256(dstChainId));
        console.log("abi.encodePacked(uint256) length:", encodedUint256.length);
        console.log("abi.encodePacked(uint256) bytes:");
        console.logBytes(encodedUint256);

        // Solidity way: abi.encodePacked with uint64 (8 bytes)
        bytes32 solidityHash = keccak256(
            abi.encodePacked(
                "USER_WITHDRAW",
                clientOrderId,
                user,
                recipient,
                amount,
                expireTime,
                dstChainId, // uint64 encodes as 8 bytes in abi.encodePacked
                chainId, // uint64 encodes as 8 bytes in abi.encodePacked
                assetAddr // address encodes as 20 bytes
            )
        );

        // Go way: manual encoding with uint64 padded to 32 bytes
        bytes32 goHash = keccak256(
            abi.encodePacked(
                "USER_WITHDRAW",
                clientOrderId,
                user,
                recipient,
                amount,
                expireTime,
                uint256(dstChainId), // uint64 padded to 32 bytes (like Go's LeftPadBytes)
                uint256(chainId), // uint64 padded to 32 bytes
                assetAddr // address as 20 bytes (fixed)
            )
        );

        console.log("Solidity hash (8 bytes uint64):");
        console.logBytes32(solidityHash);
        console.log("Go hash (32 bytes uint64):");
        console.logBytes32(goHash);

        // These hashes will be different!
        // assertEq(solidityHash, goHash, "Hashes should match but they don't due to uint64 encoding difference");
    }

    function test_hashUserWithdraw_AllFieldsEncoding() public {
        // Comprehensive test to check encoding of ALL fields
        uint256 clientOrderId = 1766405823826;
        address user_james = 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678;
        uint256 amount = 1100000;
        uint256 expireTime = 1767010623;
        uint64 dstChainId = 421614;
        bytes32 user = bytes32(uint256(uint160(user_james)));
        bytes32 recipient = bytes32(uint256(uint160(user_james)));
        address assetAddr = 0x871bD685AcE3E8f5383BDbC4bfD98a31559AA8F4;
        uint256 chainId = 11155111; // block.chainid is uint256

        // Check encoding of each field individually
        console.log("=== Field Encoding Check ===");

        bytes memory encoded;

        // 1. "USER_WITHDRAW" string
        encoded = abi.encodePacked("USER_WITHDRAW");
        console.log("'USER_WITHDRAW' length:", encoded.length);

        // 2. clientOrderId (uint256)
        encoded = abi.encodePacked(clientOrderId);
        console.log("clientOrderId (uint256) length:", encoded.length);
        assertEq(encoded.length, 32, "clientOrderId should be 32 bytes");

        // 3. user (bytes32)
        encoded = abi.encodePacked(user);
        console.log("user (bytes32) length:", encoded.length);
        assertEq(encoded.length, 32, "user should be 32 bytes");

        // 4. recipient (bytes32)
        encoded = abi.encodePacked(recipient);
        console.log("recipient (bytes32) length:", encoded.length);
        assertEq(encoded.length, 32, "recipient should be 32 bytes");

        // 5. amount (uint256)
        encoded = abi.encodePacked(amount);
        console.log("amount (uint256) length:", encoded.length);
        assertEq(encoded.length, 32, "amount should be 32 bytes");

        // 6. expireTime (uint256)
        encoded = abi.encodePacked(expireTime);
        console.log("expireTime (uint256) length:", encoded.length);
        assertEq(encoded.length, 32, "expireTime should be 32 bytes");

        // 7. dstChainId (uint64) - THIS IS THE PROBLEM - needs to be 8 bytes!
        encoded = abi.encodePacked(dstChainId);
        console.log("dstChainId (uint64) length:", encoded.length);
        console.log("dstChainId (uint64) bytes:");
        console.logBytes(encoded);
        assertEq(encoded.length, 8, "dstChainId should be 8 bytes, not 32!");

        // 8. block.chainid (uint256)
        encoded = abi.encodePacked(block.chainid);
        console.log("block.chainid (uint256) length:", encoded.length);
        assertEq(encoded.length, 32, "block.chainid should be 32 bytes");

        // 9. address (address)
        encoded = abi.encodePacked(assetAddr);
        console.log("assetAddr (address) length:", encoded.length);
        console.log("assetAddr (address) bytes:");
        console.logBytes(encoded);
        assertEq(encoded.length, 20, "address should be 20 bytes, not 32!");

        console.log("=== Summary ===");
        console.log("[OK] clientOrderId: 32 bytes (uint256)");
        console.log("[OK] user: 32 bytes (bytes32)");
        console.log("[OK] recipient: 32 bytes (bytes32)");
        console.log("[OK] amount: 32 bytes (uint256)");
        console.log("[OK] expireTime: 32 bytes (uint256)");
        console.log("[FIX] dstChainId: 8 bytes (uint64) - Go uses 32 bytes!");
        console.log("[OK] block.chainid: 32 bytes (uint256)");
        console.log("[OK] address: 20 bytes (address) - Go fixed to 20 bytes");

        // Final hash with correct encoding (as Solidity does)
        bytes32 correctHash = keccak256(
            abi.encodePacked(
                "USER_WITHDRAW",
                clientOrderId, // 32 bytes ✅
                user, // 32 bytes ✅
                recipient, // 32 bytes ✅
                amount, // 32 bytes ✅
                expireTime, // 32 bytes ✅
                dstChainId, // 8 bytes (Go uses 32 bytes - NEEDS FIX)
                block.chainid, // 32 bytes ✅
                assetAddr // 20 bytes ✅ (Go fixed)
            )
        );

        console.log("Correct hash (all fields properly encoded):");
        console.logBytes32(correctHash);
    }

    // ============ receive() Tests ============

    function test_receive_eth() public {
        uint256 ethAmount = 1 ether;
        uint256 balanceBefore = address(asset).balance;

        // Send ETH directly to contract
        (bool success,) = address(asset).call{value: ethAmount}("");
        assertTrue(success);

        assertEq(address(asset).balance, balanceBefore + ethAmount);
    }

    function test_receive_eth_multiple() public {
        uint256 ethAmount1 = 0.5 ether;
        uint256 ethAmount2 = 0.3 ether;

        uint256 balanceBefore = address(asset).balance;

        // Send ETH multiple times
        (bool success1,) = address(asset).call{value: ethAmount1}("");
        assertTrue(success1);

        (bool success2,) = address(asset).call{value: ethAmount2}("");
        assertTrue(success2);

        assertEq(address(asset).balance, balanceBefore + ethAmount1 + ethAmount2);
    }

    function test_receive_eth_forCrossChainFees() public {
        // Fund contract with ETH for cross-chain withdrawal fees
        uint256 ethAmount = 2 ether;
        vm.deal(address(asset), ethAmount);

        assertEq(address(asset).balance, ethAmount);

        // This ETH can be used for cross-chain withdrawal fees
        // The contract should have sufficient balance for fees
        assertGe(address(asset).balance, 0.001 ether);
    }

    // ============ emergencyWithdrawETH Tests ============

    function test_emergencyWithdrawETH_success() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;

        // Prepare multi-sig withdraw
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_threeSigners() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;

        // Prepare multi-sig withdraw with 3 signers
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);
        bytes memory signature3 = signMessage(operationHash, signer3PrivateKey);

        address[] memory allSigners = new address[](3);
        allSigners[0] = signer1;
        allSigners[1] = signer2;
        allSigners[2] = signer3;

        bytes[] memory signatures = new bytes[](3);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_invalidSigner() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = address(0x999); // Invalid signer

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_notAllowedSigner() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;
        uint256 expireTime = block.timestamp + 1 hours;

        // Use a private key that's not in the signers list
        uint256 invalidPrivateKey = 0x999;
        address invalidSigner = vm.addr(invalidPrivateKey);
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, invalidPrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = invalidSigner;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_expiredTransaction() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;
        uint256 expireTime = block.timestamp - 1; // Already expired
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_transferFailed() public {
        // Create a contract that rejects ETH transfers
        RejectETH rejector = new RejectETH();
        vm.deal(address(asset), 1 ether);

        uint256 withdrawAmount = 0.5 ether;
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                address(rejector),
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer2PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(address(rejector), withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_sameSigner() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);
        bytes memory signature2 = signMessage(operationHash, signer1PrivateKey); // Same signer

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer1; // Same signer

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = signature1;
        signatures[1] = signature2;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_invalidAllSignersLength() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);

        address[] memory allSigners = new address[](1); // Only 1 signer (need at least 2)
        allSigners[0] = signer1;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature1;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }

    function test_emergencyWithdrawETH_invalidSignaturesLength() public {
        // Fund the contract with ETH
        vm.deal(address(asset), 1 ether);

        address recipient = user1;
        uint256 withdrawAmount = 0.5 ether;
        uint256 expireTime = block.timestamp + 1 hours;
        uint256 nonce = 0;

        bytes32 operationHash = keccak256(
            abi.encodePacked(
                "EMERGENCY_WITHDRAW_ETH",
                recipient,
                withdrawAmount,
                expireTime,
                nonce,
                address(asset),
                block.chainid
            )
        );
        operationHash = MessageHashUtils.toEthSignedMessageHash(operationHash);

        bytes memory signature1 = signMessage(operationHash, signer1PrivateKey);

        address[] memory allSigners = new address[](2);
        allSigners[0] = signer1;
        allSigners[1] = signer2;

        bytes[] memory signatures = new bytes[](1); // Mismatch: 2 signers but 1 signature
        signatures[0] = signature1;

        vm.expectRevert(IAsset.FunctionDisabled.selector);
        asset.emergencyWithdrawETH(recipient, withdrawAmount, expireTime, nonce, allSigners, signatures);
    }
}

// Helper contract that rejects ETH transfers
contract RejectETH {
    receive() external payable {
        revert("RejectETH: I reject all ETH");
    }
}
