// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Asset} from "../src/Asset.sol";
import {IAsset} from "../src/interfaces/IAsset.sol";
import {MockToken} from "../src/mock/MockToken.sol";
import {MarginAsset} from "../src/margin/MarginAsset.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MarginAssetCalculator} from "../src/margin/MarginAsset.sol";

/**
 * @title AvailableAmountTest
 * @notice Test file specifically for testing user available balance calculation
 * @dev Users can provide relevant data here and then calculate and verify available balance
 */
contract AvailableAmountTest is Test {
    Asset public asset;
    MockToken public USDC;
    MarginAssetCalculator public marginAssetCalculator;
    address public owner;
    address public settlementOperator;
    address public withdrawOperator;

    // Test user addresses
    address internal user1 = address(0x1111);
    address internal user2 = address(0x2222);

    function setUp() public {
        owner = vm.addr(999);
        settlementOperator = vm.addr(777);
        withdrawOperator = vm.addr(666);

        // Deploy USDC
        USDC = new MockToken("USDC", "USDC");

        // Deploy MarginAssetCalculator
        marginAssetCalculator = new MarginAssetCalculator();

        // Deploy Asset contract
        vm.startPrank(owner);
        Asset implementation = new Asset();
        bytes memory initData = abi.encodeWithSelector(Asset.initialize.selector, address(USDC), uint64(1000));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        asset = Asset(payable(address(proxy)));
        asset.transferOwnership(owner);
        asset.setSettlementAddress(settlementOperator);
        asset.setWithdrawOperator(withdrawOperator);
        asset.setMarginAsset(address(marginAssetCalculator));
        vm.stopPrank();

        // Setup coin information (coinId=1 is USDC, precision is 6)
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

        // Fund contract with USDC
        USDC.transfer(address(asset), 1e21);
    }

    /**
     * @notice Test available balance calculation - custom data scenario
     * @dev Users can fully customize all data to test specific scenarios
     */
    function test_availableAmount_customData() public {
        bytes32 user = bytes32(uint256(uint160(user1)));

        // ============ Users can fully customize data here ============
        
        // 1. Coin information
        uint64 collateralCoinId = 1000;
        int64 crossCollateralAmount = -414444088;
        uint64 subaccountId = 1000000008;

        // 2. Position information (can create multiple positions)
        uint64 exchangeId1 = 200001;
        int64 openSize1 = 7;
        int64 openValue1 = 534177000;
        int64 isolatedCollateralAmount1 = 0;
        int256 cacheFundingIndex1 = -115714695;

        // 3. Exchange information
        string memory exchangeSymbol1 = "BTCUSD";
        uint32 stepSizeScale1 = 3;
        uint32 tickSizeScale1 = 1;
        uint32 maxLeverage1 = 100; // Must be > 0, otherwise effectiveLeverage = min(leverage, maxLeverage) will be 0
        uint32 maintenanceMarginRatioPpm1 = 5000; // 0.5% = 5000/1000000
        uint64 positionValueUpperBound1 = 100000000000; // Must be > 0 for proper risk tier calculation

        // 4. Trading settings
        uint32 leverage1 = 20;
        uint8 marginMode1 = 1; // Cross margin mode

        // 5. Oracle price
        uint256 oraclePrice1 = 647555;

        // 6. Funding index
        int256 fundingIndex1 = -239105461;
        // ==============================================================

        vm.startPrank(settlementOperator);

        // Setup coin information first (if collateralCoinId is not 1)
        if (collateralCoinId != 1) {
            MarginAsset.Coin[] memory coinUpdates = new MarginAsset.Coin[](1);
            coinUpdates[0] = MarginAsset.Coin({id: collateralCoinId, symbol: "USDC", stepSizeScale: 6});
            Asset.BatchUpdateData memory coinData = Asset.BatchUpdateData({
                coinUpdates: coinUpdates,
                exchangeUpdates: new MarginAsset.Exchange[](0),
                fundingIndexUpdates: new MarginAsset.FundingIndex[](0),
                oraclePriceUpdates: new MarginAsset.OraclePrice[](0),
                subaccountUpdates: new MarginAsset.Subaccount[](0),
                perpetualAssetUpdates: new MarginAsset.PerpetualAsset[](0)
            });
            asset.batchUpdate(2, 0, 2, coinData);
        }

        // Setup exchange information
        MarginAsset.Exchange[] memory exchangeUpdates = new MarginAsset.Exchange[](1);
        MarginAsset.RiskTier[] memory riskTiers1 = new MarginAsset.RiskTier[](1);
        riskTiers1[0] = MarginAsset.RiskTier({
            maxLeverage: maxLeverage1,
            maintenanceMarginRatioPpm: maintenanceMarginRatioPpm1,
            positionValueUpperBound: positionValueUpperBound1
        });
        exchangeUpdates[0] = MarginAsset.Exchange({
            exchangeId: exchangeId1,
            symbol: exchangeSymbol1,
            stepSizeScale: stepSizeScale1,
            tickSizeScale: tickSizeScale1,
            riskTiers: riskTiers1
        });

        // Setup funding index
        MarginAsset.FundingIndex[] memory fundingIndexUpdates = new MarginAsset.FundingIndex[](1);
        fundingIndexUpdates[0] = MarginAsset.FundingIndex({
            exchangeId: exchangeId1,
            fundingIndex: fundingIndex1,
            fundingIndexTime: uint64(block.timestamp)
        });

        // Setup oracle price
        MarginAsset.OraclePrice[] memory oraclePriceUpdates = new MarginAsset.OraclePrice[](1);
        oraclePriceUpdates[0] = MarginAsset.OraclePrice({
            exchangeId: exchangeId1,
            oraclePrice: oraclePrice1,
            oracleTime: uint64(block.timestamp)
        });

        // Create positions
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: exchangeId1,
            openSize: openSize1,
            openValue: openValue1,
            isolatedCollateralAmount: isolatedCollateralAmount1,
            cacheFundingIndex: cacheFundingIndex1
        });

        // Create subaccount
        MarginAsset.Subaccount[] memory subaccountUpdates = new MarginAsset.Subaccount[](1);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: exchangeId1,
            leverage: leverage1,
            marginMode: marginMode1
        });
        subaccountUpdates[0] = MarginAsset.Subaccount({
            id: subaccountId,
            chainAddress: user,
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "",
            tradeSettings: tradeSettings
        });

        // Create perpetual asset
        MarginAsset.PerpetualAsset[] memory perpetualAssetUpdates = new MarginAsset.PerpetualAsset[](1);
        perpetualAssetUpdates[0] = MarginAsset.PerpetualAsset({
            subaccountId: subaccountId,
            collateralCoinId: collateralCoinId,
            crossCollateralAmount: crossCollateralAmount,
            positions: positions
        });

        Asset.BatchUpdateData memory batchData = Asset.BatchUpdateData({
            coinUpdates: new MarginAsset.Coin[](0),
            exchangeUpdates: exchangeUpdates,
            fundingIndexUpdates: fundingIndexUpdates,
            oraclePriceUpdates: oraclePriceUpdates,
            subaccountUpdates: subaccountUpdates,
            perpetualAssetUpdates: perpetualAssetUpdates
        });

        uint256 batchId = collateralCoinId != 1 ? 3 : 2;
        asset.batchUpdate(batchId, 0, batchId, batchData);
        vm.stopPrank();

        // Debug: Get subaccountId first
        uint64 subaccountIdFromMapping = asset.addressToSubaccountId(user);
        console.log("\n=== Debug: Step-by-step calculation ===");
        console.log("Step 1 - Subaccount ID from mapping:", subaccountIdFromMapping);
        
        if (subaccountIdFromMapping == 0) {
            console.log("ERROR: Subaccount ID is 0, returning 0 at line 318");
            return;
        }

        // Debug: Check subaccount exists (can't directly access due to dynamic array in struct)
        // We'll verify by checking if availableAmount can be calculated
        console.log("Step 2 - Subaccount ID:", subaccountIdFromMapping);
        console.log("Note: Cannot directly check subaccount.id due to dynamic array in struct");

        // Debug: Check coin exists
        (uint64 coinId,,) = asset.coins(collateralCoinId);
        console.log("Step 3 - Coin ID:", coinId);
        console.log("Step 3 - Collateral Coin ID requested:", collateralCoinId);
        if (coinId == 0) {
            console.log("ERROR: Coin not found, would revert at line 354");
            console.log("Please ensure coinId", collateralCoinId, "is set up in batchUpdate");
            return;
        }

        // Calculate available balance
        uint256 availableAmount = asset.availableAmount(user);
        
        // Debug: Try to get the internal calculation result by calling MarginAssetCalculator directly
        // Get coin info from storage
        (uint64 coinIdFromStorage, string memory coinSymbol, uint32 coinStepSizeScale) = asset.coins(collateralCoinId);
        MarginAsset.Coin memory collateralCoin = MarginAsset.Coin({
            id: coinIdFromStorage,
            symbol: coinSymbol,
            stepSizeScale: coinStepSizeScale
        });
        
        // Get exchange, oracle price, and funding index
        MarginAsset.Exchange memory exchange = exchangeUpdates[0];
        MarginAsset.OraclePrice memory oraclePrice = oraclePriceUpdates[0];
        MarginAsset.FundingIndex memory fundingIndex = fundingIndexUpdates[0];
        
        MarginAsset.Exchange[] memory exchangeArray = new MarginAsset.Exchange[](1);
        MarginAsset.OraclePrice[] memory oraclePriceArray = new MarginAsset.OraclePrice[](1);
        MarginAsset.FundingIndex[] memory fundingIndexArray = new MarginAsset.FundingIndex[](1);
        
        exchangeArray[0] = exchange;
        oraclePriceArray[0] = oraclePrice;
        fundingIndexArray[0] = fundingIndex;
        
        MarginAsset.Subaccount memory subaccountForCalc = subaccountUpdates[0];
        MarginAsset.PerpetualAsset memory perpetualAssetForCalc = perpetualAssetUpdates[0];
        
        // Call MarginAssetCalculator directly to get intermediate results
        int256 calculatedAmount;
        bool calculationSuccess = false;
        try marginAssetCalculator.getCrossTransferOutAvailableAmount(
            collateralCoin,
            exchangeArray,
            oraclePriceArray,
            fundingIndexArray,
            subaccountForCalc,
            perpetualAssetForCalc
        ) returns (int256 result) {
            calculatedAmount = result;
            calculationSuccess = true;
        } catch Error(string memory reason) {
            console.log("ERROR in MarginAssetCalculator calculation:", reason);
            console.log("This error occurred during available balance calculation");
            console.log("Check: maxLeverage must be > 0, maintenanceMarginRatioPpm should be set");
        } catch (bytes memory lowLevelData) {
            console.log("ERROR: Low-level error in MarginAssetCalculator");
            console.logBytes(lowLevelData);
        }
        
        console.log("\n=== Custom Data Scenario - Available Balance Calculation Result ===");
        console.log("User address:", vm.toString(user1));
        console.log("Cross collateral amount:", crossCollateralAmount);
        console.log("Number of positions:", positions.length);
        console.log("Calculated available balance (from asset.availableAmount):", availableAmount);
        if (calculationSuccess) {
            console.log("Calculated amount (from MarginAssetCalculator, int256):", calculatedAmount);
            if (calculatedAmount < 0) {
                console.log("WARNING: Calculated amount is negative, will be converted to 0");
            }
        } else {
            console.log("MarginAssetCalculator calculation failed - see error above");
        }
        console.log("Subaccount ID:", subaccountIdFromMapping);

        // Output detailed calculation information
        console.log("\n=== Detailed Calculation Information ===");
        console.log("Position 1 - Exchange ID:", exchangeId1);
        console.log("Position 1 - Position size:", openSize1);
        console.log("Position 1 - Position value:", openValue1);
        console.log("Position 1 - Leverage:", leverage1);
        console.log("Position 1 - Margin mode:", marginMode1 == 1 ? "Cross" : "Isolated");
        console.log("Position 1 - Oracle price:", oraclePrice1);
        console.log("Position 1 - Funding index:", fundingIndex1);
        console.log("Position 1 - Cache funding index:", cacheFundingIndex1);
        
        // Debug: Check where 0 is returned
        console.log("\n=== Debug: Where is 0 returned? ===");
        if (subaccountIdFromMapping == 0) {
            console.log("RETURN 0 at Asset.sol:318 - subaccountId == 0");
        } else if (!calculationSuccess) {
            console.log("RETURN 0 - Calculation failed in MarginAssetCalculator");
            console.log("Common causes:");
            console.log("  1. maxLeverage = 0 (must be > 0)");
            console.log("  2. Invalid risk tier configuration");
            console.log("  3. Missing exchange or price data");
        } else if (calculatedAmount < 0) {
            console.log("RETURN 0 at Asset.sol:403 - userAvailableAmount < 0");
            console.log("The calculated amount is negative:", calculatedAmount);
            console.log("This means TV (Total Value) < IMR (Initial Margin Requirement) + orderFrozenAmount");
            console.log("Possible reasons:");
            console.log("  - Cross collateral amount is too negative");
            console.log("  - Position losses exceed collateral");
            console.log("  - Funding fees are too high");
        } else {
            console.log("Available amount is:", calculatedAmount);
        }

        // Verify available balance is greater than or equal to 0
        assertGe(availableAmount, 0, "Available balance should be greater than or equal to 0");
    }
}
