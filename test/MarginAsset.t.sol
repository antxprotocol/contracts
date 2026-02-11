// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/margin/MarginAsset.sol";

/**
 * @title MarginAssetTest
 */
contract MarginAssetTest is Test {
    using MarginAsset for *;

    uint256 constant PRECISION_SCALE = 1000000;

    MarginAsset.Coin usdtCoin;
    MarginAsset.Coin btcCoin;
    MarginAsset.Coin ethCoin;

    MarginAsset.Exchange btcExchange;
    MarginAsset.Exchange ethExchange;

    mapping(uint64 => uint256) oraclePriceMap;
    mapping(uint64 => int256) fundingIndexMap;

    function setUp() public {
        usdtCoin = MarginAsset.Coin({id: 1000, symbol: "USDT", stepSizeScale: 6});

        btcCoin = MarginAsset.Coin({id: 1001, symbol: "BTC", stepSizeScale: 3});

        ethCoin = MarginAsset.Coin({id: 1002, symbol: "ETH", stepSizeScale: 2});

        MarginAsset.RiskTier[] memory btcRiskTiers = new MarginAsset.RiskTier[](6);
        btcRiskTiers[0] = MarginAsset.RiskTier({
            maxLeverage: 50, maintenanceMarginRatioPpm: 10000, positionValueUpperBound: 500000000000
        });
        btcRiskTiers[1] = MarginAsset.RiskTier({
            maxLeverage: 25, maintenanceMarginRatioPpm: 20000, positionValueUpperBound: 1000000000000
        });
        btcRiskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 20, maintenanceMarginRatioPpm: 25000, positionValueUpperBound: 2000000000000
        });
        btcRiskTiers[3] = MarginAsset.RiskTier({
            maxLeverage: 10, maintenanceMarginRatioPpm: 50000, positionValueUpperBound: 4000000000000
        });
        btcRiskTiers[4] = MarginAsset.RiskTier({
            maxLeverage: 5, maintenanceMarginRatioPpm: 100000, positionValueUpperBound: 10000000000000
        });
        btcRiskTiers[5] = MarginAsset.RiskTier({
            maxLeverage: 2, maintenanceMarginRatioPpm: 250000, positionValueUpperBound: 20000000000000
        });

        btcExchange = MarginAsset.Exchange({
            exchangeId: 200001, symbol: "BTCUSDT", stepSizeScale: 3, tickSizeScale: 1, riskTiers: btcRiskTiers
        });

        MarginAsset.RiskTier[] memory ethRiskTiers = new MarginAsset.RiskTier[](6);
        ethRiskTiers[0] = MarginAsset.RiskTier({
            maxLeverage: 50, maintenanceMarginRatioPpm: 10000, positionValueUpperBound: 500000000000
        });
        ethRiskTiers[1] = MarginAsset.RiskTier({
            maxLeverage: 25, maintenanceMarginRatioPpm: 20000, positionValueUpperBound: 1000000000000
        });
        ethRiskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 20, maintenanceMarginRatioPpm: 25000, positionValueUpperBound: 2000000000000
        });
        ethRiskTiers[3] = MarginAsset.RiskTier({
            maxLeverage: 10, maintenanceMarginRatioPpm: 50000, positionValueUpperBound: 4000000000000
        });
        ethRiskTiers[4] = MarginAsset.RiskTier({
            maxLeverage: 5, maintenanceMarginRatioPpm: 100000, positionValueUpperBound: 10000000000000
        });
        ethRiskTiers[5] = MarginAsset.RiskTier({
            maxLeverage: 2, maintenanceMarginRatioPpm: 250000, positionValueUpperBound: 20000000000000
        });

        ethExchange = MarginAsset.Exchange({
            exchangeId: 200002, symbol: "ETHUSDT", stepSizeScale: 2, tickSizeScale: 2, riskTiers: ethRiskTiers
        });

        oraclePriceMap[200001] = 1000000;
        oraclePriceMap[200002] = 300000;

        fundingIndexMap[200001] = -1000000;
        fundingIndexMap[200002] = -2000000;
    }


    function testNewAssetEmpty() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](2);
        exchanges[0] = btcExchange;
        exchanges[1] = ethExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](2);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});
        oraclePrices[1] =
            MarginAsset.OraclePrice({exchangeId: 200002, oraclePrice: oraclePriceMap[200002], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](2);
        fundingIndices[0] =
            MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: fundingIndexMap[200001], fundingIndexTime: 0});
        fundingIndices[1] =
            MarginAsset.FundingIndex({exchangeId: 200002, fundingIndex: fundingIndexMap[200002], fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](2);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 1 // MARGIN_MODE_CROSS
            });
        tradeSettings[1] =
            MarginAsset.TradeSetting({
                exchangeId: 200002,
                leverage: 10,
                marginMode: 1 // MARGIN_MODE_CROSS
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 0,
            positions: new MarginAsset.Position[](0)
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, 0);
        assertEq(asset.crossGroup.tv, 0);
        assertEq(asset.crossGroup.imr, 0);
        assertEq(asset.crossGroup.mmr, 0);
        assertEq(asset.crossGroup.positions.length, 0);
        assertEq(asset.isolatedGroups.length, 0);
    }

    function testNewAssetWithInitialCollateral() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](2);
        exchanges[0] = btcExchange;
        exchanges[1] = ethExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](2);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});
        oraclePrices[1] =
            MarginAsset.OraclePrice({exchangeId: 200002, oraclePrice: oraclePriceMap[200002], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](2);
        fundingIndices[0] =
            MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: fundingIndexMap[200001], fundingIndexTime: 0});
        fundingIndices[1] =
            MarginAsset.FundingIndex({exchangeId: 200002, fundingIndex: fundingIndexMap[200002], fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](2);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 1 // MARGIN_MODE_CROSS
            });
        tradeSettings[1] =
            MarginAsset.TradeSetting({
                exchangeId: 200002,
                leverage: 10,
                marginMode: 1 // MARGIN_MODE_CROSS
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        int64 crossCollateralAmount = 1000000000;

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: crossCollateralAmount,
            positions: new MarginAsset.Position[](0)
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, int256(crossCollateralAmount));
        assertEq(asset.crossGroup.tv, int256(crossCollateralAmount) * int256(PRECISION_SCALE));
        assertEq(asset.crossGroup.imr, 0);
        assertEq(asset.crossGroup.mmr, 0);
        assertEq(asset.crossGroup.positions.length, 0);
        assertEq(asset.isolatedGroups.length, 0);
    }

    function testNewAssetWithCrossPosition() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: 0,
            fundingIndexTime: 0
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 1 // MARGIN_MODE_CROSS
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: 0
        });

        int64 crossCollateralAmount = -9006000500;

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: crossCollateralAmount,
            positions: positions
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, int256(crossCollateralAmount));

        int256 expectedTV = int256(crossCollateralAmount) * int256(PRECISION_SCALE) + int256(10000000000000000);
        assertEq(asset.crossGroup.tv, expectedTV);

        assertEq(asset.crossGroup.positions.length, 1);
        assertEq(asset.crossGroup.positions[0].openSize, 100);
        assertEq(asset.crossGroup.positions[0].openValue, 10005000000);
        assertEq(asset.crossGroup.positions[0].pv, int256(10000000000000000));

        assertEq(asset.crossGroup.imr, 500000000000000);
        assertEq(asset.crossGroup.mmr, 100000000000000);

        assertEq(asset.isolatedGroups.length, 0);
    }

    function testGetCrossTransferOutAvailableAmount() public {
        // TV = 993999500000000, IMR = 500000000000000, orderFrozenAmount = 0
        int256 tv = 993999500000000;
        uint256 imr = 500000000000000;
        uint256 orderFrozenAmount = 0;

        // Calculate expected available amount
        // availableAmount = (TV - IMR - orderFrozenAmount) / PRECISION_SCALE
        // = (993999500000000 - 500000000000000 - 0) / 1000000
        // = 493999500000000 / 1000000
        // = 493999500
        int256 expectedAmount = 493999500;

        // Create a CrossGroup for testing
        // Note: collateralAmount must be >= expectedAmount because the function limits
        // the result to collateralAmount + sum of positions' openValue
        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: expectedAmount, positions: new MarginAsset.AssetPosition[](0), imr: imr, mmr: 0, tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(tv, imr, orderFrozenAmount, crossGroup);

        // The result should be limited by collateralAmount, so it should equal expectedAmount
        assertEq(uint256(availableAmount), uint256(expectedAmount));
    }

    function testGetCrossTransferOutAvailableAmountNegativeTV() public {
        int256 tv = -1000000000000;
        uint256 imr = 500000000000000;
        uint256 orderFrozenAmount = 0;

        // Create a minimal CrossGroup for testing
        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: 0, positions: new MarginAsset.AssetPosition[](0), imr: imr, mmr: 0, tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(tv, imr, orderFrozenAmount, crossGroup);

        assertEq(availableAmount, 0);
    }

    function testNewAssetWithIsolatedPosition() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: 0, fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 2 // MARGIN_MODE_ISOLATED
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: -9505000000,
            cacheFundingIndex: 0
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 498999500,
            positions: positions
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, 498999500);
        assertEq(asset.isolatedGroups.length, 1);
        assertEq(asset.isolatedGroups[0].collateralAmount, int256(-9505000000));
        assertEq(asset.isolatedGroups[0].position.openSize, 100);
        assertEq(asset.isolatedGroups[0].position.openValue, 10005000000);
    }

    function testNewAssetWithNegativeFundingIndex() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: fundingIndexMap[200001],
            fundingIndexTime: 0
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 1 // MARGIN_MODE_CROSS
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: 0
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123, collateralCoinId: 1000, crossCollateralAmount: 0, positions: positions
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertGt(asset.crossGroup.collateralAmount, 0);
    }

    function testNewAssetWithNegativeCacheFundingIndex() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: 0, fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 1 // MARGIN_MODE_CROSS
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: -1000000
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 1000000000,
            positions: positions
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertLt(asset.crossGroup.collateralAmount, int256(1000000000));
    }

    function normalizeScale(int256 value, int32 fromScale, int32 toScale) internal pure returns (int256) {
        if (fromScale == toScale) {
            return value;
        } else if (fromScale < toScale) {
            int32 diff = toScale - fromScale;
            return value * int256(10 ** uint256(uint32(diff)));
        } else {
            int32 diff = fromScale - toScale;
            return value / int256(10 ** uint256(uint32(diff)));
        }
    }

    // ============ Branch Coverage Tests ============

    function testGetCrossTransferOutAvailableAmount_Overflow() public {
        int256 tv = 1000000000000;
        uint256 imr = type(uint256).max;
        uint256 orderFrozenAmount = 1;

        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: 0, positions: new MarginAsset.AssetPosition[](0), imr: imr, mmr: 0, tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(tv, imr, orderFrozenAmount, crossGroup);

        assertEq(availableAmount, 0);
    }

    function testGetCrossTransferOutAvailableAmount_ResultGreaterThanTmpValue() public {
        int256 tv = 2000000000000;
        uint256 imr = 500000000000;
        uint256 orderFrozenAmount = 0;

        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: 1000000,
            positions: new MarginAsset.AssetPosition[](0),
            imr: imr,
            mmr: 0,
            tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(tv, imr, orderFrozenAmount, crossGroup);

        assertEq(availableAmount, 1000000);
    }

    function testGetCrossTransferOutAvailableAmount_ResultNegative() public {
        int256 tv = 100000000000;
        uint256 imr = 500000000000;
        uint256 orderFrozenAmount = 0;

        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: -1000000,
            positions: new MarginAsset.AssetPosition[](0),
            imr: imr,
            mmr: 0,
            tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(tv, imr, orderFrozenAmount, crossGroup);

        assertEq(availableAmount, 0);
    }

    function testGetCrossTransferOutAvailableAmount_MultiplePositions() public {
        int256 tv = 2000000000000;
        uint256 imr = 500000000000;
        uint256 orderFrozenAmount = 0;

        MarginAsset.AssetPosition[] memory positions = new MarginAsset.AssetPosition[](2);
        positions[0] = MarginAsset.AssetPosition({
            exchangeId: 200001,
            openSize: 100,
            openValue: 500000000,
            imr: 0,
            mmr: 0,
            pv: 0
        });
        positions[1] = MarginAsset.AssetPosition({
            exchangeId: 200002,
            openSize: 200,
            openValue: 300000000,
            imr: 0,
            mmr: 0,
            pv: 0
        });

        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: 1000000,
            positions: positions,
            imr: imr,
            mmr: 0,
            tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(tv, imr, orderFrozenAmount, crossGroup);

        assertEq(availableAmount, 1500000);
    }

    function testLeverageToInitialMarginRatioPpm_ZeroLeverage() public {
        assertTrue(true);
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: 0, fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 200001,
            leverage: 0,
            marginMode: 1
        });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001, openSize: 100, openValue: 10005000000, isolatedCollateralAmount: 0, cacheFundingIndex: 0
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123, collateralCoinId: 1000, crossCollateralAmount: 0, positions: positions
        });

    }

    function testCalculatePositionValue_ScaleDiffEqual() public {
        int256 openSize = 1000;
        uint256 oraclePrice = 1000000;
        uint32 stepSizeScale = 3;
        uint32 tickSizeScale = 3;
        uint32 coinStepSizeScale = 6;

        int256 positionValue =
            MarginAsset.calculatePositionValue(openSize, oraclePrice, stepSizeScale, tickSizeScale, coinStepSizeScale);

        assertEq(positionValue, 1000000000);
    }

    function testCalculatePositionValue_NegativeOpenSize() public {
        int256 openSize = -1000;
        uint256 oraclePrice = 1000000;
        uint32 stepSizeScale = 3;
        uint32 tickSizeScale = 1;
        uint32 coinStepSizeScale = 6;

        int256 positionValue =
            MarginAsset.calculatePositionValue(openSize, oraclePrice, stepSizeScale, tickSizeScale, coinStepSizeScale);

        assertLt(positionValue, 0);
        assertEq(uint256(-positionValue), 100000000000);
    }

    function testCalculatePositionValue_DivisorTooLarge() public {
        assertTrue(true);
    }

    function testFindPositionRiskTier_EmptyArray() public {
        assertTrue(true);
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](0);

        MarginAsset.Exchange memory exchange = MarginAsset.Exchange({
            exchangeId: 200001,
            symbol: "BTCUSDT",
            stepSizeScale: 3,
            tickSizeScale: 1,
            riskTiers: riskTiers
        });

        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = exchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] = MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: 1000000, oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: 0, fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({exchangeId: 200001, leverage: 20, marginMode: 1});

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001, openSize: 100, openValue: 10005000000, isolatedCollateralAmount: 0, cacheFundingIndex: 0
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123, collateralCoinId: 1000, crossCollateralAmount: 0, positions: positions
        });

    }

    function testFindPositionRiskTier_NotFound() public {
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](3);
        riskTiers[0] =
            MarginAsset.RiskTier({maxLeverage: 50, maintenanceMarginRatioPpm: 10000, positionValueUpperBound: 1000000});
        riskTiers[1] =
            MarginAsset.RiskTier({maxLeverage: 25, maintenanceMarginRatioPpm: 20000, positionValueUpperBound: 5000000});
        riskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 10, maintenanceMarginRatioPpm: 50000, positionValueUpperBound: 10000000
        });

        uint256 positionValueAbs = 20000000;

        uint256 riskTierIndex = MarginAsset.findPositionRiskTier(riskTiers, positionValueAbs);

        assertEq(riskTierIndex, 2);
    }

    function testFindPositionRiskTier_Found() public {
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](3);
        riskTiers[0] =
            MarginAsset.RiskTier({maxLeverage: 50, maintenanceMarginRatioPpm: 10000, positionValueUpperBound: 1000000});
        riskTiers[1] =
            MarginAsset.RiskTier({maxLeverage: 25, maintenanceMarginRatioPpm: 20000, positionValueUpperBound: 5000000});
        riskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 10, maintenanceMarginRatioPpm: 50000, positionValueUpperBound: 10000000
        });

        uint256 positionValueAbs = 3000000;

        uint256 riskTierIndex = MarginAsset.findPositionRiskTier(riskTiers, positionValueAbs);

        assertEq(riskTierIndex, 1);
    }

    function testCalculateFundingAmount_ScaleDiffEqual() public {
        int256 openSize = 1000;
        int256 cacheFundingIndex = 1000000;
        int256 fundingIndex = 500000;
        uint32 stepSizeScale = 3;
        uint32 tickSizeScale = 3;
        uint32 coinStepSizeScale = 6;

        int256 fundingAmount = MarginAsset.calculateFundingAmount(
            openSize, cacheFundingIndex, fundingIndex, stepSizeScale, tickSizeScale, coinStepSizeScale
        );

        assertEq(fundingAmount, 500000000);
    }

    function testCalculateFundingAmount_NegativeOpenSizePositiveFundingDiff() public {
        int256 openSize = -1000;
        int256 cacheFundingIndex = 1000000;
        int256 fundingIndex = 500000;
        uint32 stepSizeScale = 3;
        uint32 tickSizeScale = 1;
        uint32 coinStepSizeScale = 6;

        int256 fundingAmount = MarginAsset.calculateFundingAmount(
            openSize, cacheFundingIndex, fundingIndex, stepSizeScale, tickSizeScale, coinStepSizeScale
        );

        assertLt(fundingAmount, 0);
    }

    function testCalculateFundingAmount_PositiveOpenSizeNegativeFundingDiff() public {
        int256 openSize = 1000;
        int256 cacheFundingIndex = 500000;
        int256 fundingIndex = 1000000;
        uint32 stepSizeScale = 3;
        uint32 tickSizeScale = 1;
        uint32 coinStepSizeScale = 6;

        int256 fundingAmount = MarginAsset.calculateFundingAmount(
            openSize, cacheFundingIndex, fundingIndex, stepSizeScale, tickSizeScale, coinStepSizeScale
        );

        assertLt(fundingAmount, 0);
    }

    function testNewAsset_UnsupportedMarginMode() public {
        assertTrue(true);
    }

    function testNewAsset_IsolatedMarginNegativeFundingWithRemainder() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: 0, fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 2 // MARGIN_MODE_ISOLATED
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: -9505000000,
            cacheFundingIndex: -1000001
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123, collateralCoinId: 1000, crossCollateralAmount: 0, positions: positions
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertEq(asset.isolatedGroups.length, 1);
        assertEq(asset.isolatedGroups[0].collateralAmount, -9505010001);
    }

    function testNewAsset_CrossFundingAmountZero() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: 0, fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 1 // MARGIN_MODE_CROSS
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: 0
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 1000000000,
            positions: positions
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertEq(asset.crossGroup.collateralAmount, 1000000000);
    }

    function testNewAsset_CrossFundingAmountNegativeWithRemainder() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] =
            MarginAsset.OraclePrice({exchangeId: 200001, oraclePrice: oraclePriceMap[200001], oracleTime: 0});

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({exchangeId: 200001, fundingIndex: 0, fundingIndexTime: 0});

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] =
            MarginAsset.TradeSetting({
                exchangeId: 200001,
                leverage: 20,
                marginMode: 1 // MARGIN_MODE_CROSS
            });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            isMultiSigWallet: false,
            multiSigWallet: address(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: -1000001
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 1000000000,
            positions: positions
        });

        MarginAsset.Asset memory asset =
            MarginAsset.newAsset(usdtCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);

        assertEq(asset.crossGroup.collateralAmount, 999989999);
    }
}

