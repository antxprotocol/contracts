// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/margin/MarginAsset.sol";

/**
 * @title MarginAssetTest
 * @notice 测试 MarginAsset 合约，与 Go 测试用例保持一致
 */
contract MarginAssetTest is Test {
    using MarginAsset for *;

    // 测试常量
    uint256 constant PRECISION_SCALE = 1000000;

    // 币种信息
    MarginAsset.Coin usdtCoin;
    MarginAsset.Coin btcCoin;
    MarginAsset.Coin ethCoin;

    // 交易所信息
    MarginAsset.Exchange btcExchange;
    MarginAsset.Exchange ethExchange;

    // Oracle价格和资金费率
    mapping(uint64 => uint256) oraclePriceMap;
    mapping(uint64 => int256) fundingIndexMap;

    function setUp() public {
        // 初始化币种信息
        usdtCoin = MarginAsset.Coin({
            id: 1000,
            symbol: "USDT",
            stepSizeScale: 6
        });

        btcCoin = MarginAsset.Coin({
            id: 1001,
            symbol: "BTC",
            stepSizeScale: 3
        });

        ethCoin = MarginAsset.Coin({
            id: 1002,
            symbol: "ETH",
            stepSizeScale: 2
        });

        // 初始化BTC交易所
        MarginAsset.RiskTier[] memory btcRiskTiers = new MarginAsset.RiskTier[](6);
        btcRiskTiers[0] = MarginAsset.RiskTier({
            maxLeverage: 50,
            maintenanceMarginRatioPpm: 10000,
            positionValueUpperBound: 500000000000
        });
        btcRiskTiers[1] = MarginAsset.RiskTier({
            maxLeverage: 25,
            maintenanceMarginRatioPpm: 20000,
            positionValueUpperBound: 1000000000000
        });
        btcRiskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 20,
            maintenanceMarginRatioPpm: 25000,
            positionValueUpperBound: 2000000000000
        });
        btcRiskTiers[3] = MarginAsset.RiskTier({
            maxLeverage: 10,
            maintenanceMarginRatioPpm: 50000,
            positionValueUpperBound: 4000000000000
        });
        btcRiskTiers[4] = MarginAsset.RiskTier({
            maxLeverage: 5,
            maintenanceMarginRatioPpm: 100000,
            positionValueUpperBound: 10000000000000
        });
        btcRiskTiers[5] = MarginAsset.RiskTier({
            maxLeverage: 2,
            maintenanceMarginRatioPpm: 250000,
            positionValueUpperBound: 20000000000000
        });

        btcExchange = MarginAsset.Exchange({
            exchangeId: 200001,
            symbol: "BTCUSDT",
            stepSizeScale: 3,
            tickSizeScale: 1,
            riskTiers: btcRiskTiers
        });

        // 初始化ETH交易所
        MarginAsset.RiskTier[] memory ethRiskTiers = new MarginAsset.RiskTier[](6);
        ethRiskTiers[0] = MarginAsset.RiskTier({
            maxLeverage: 50,
            maintenanceMarginRatioPpm: 10000,
            positionValueUpperBound: 500000000000
        });
        ethRiskTiers[1] = MarginAsset.RiskTier({
            maxLeverage: 25,
            maintenanceMarginRatioPpm: 20000,
            positionValueUpperBound: 1000000000000
        });
        ethRiskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 20,
            maintenanceMarginRatioPpm: 25000,
            positionValueUpperBound: 2000000000000
        });
        ethRiskTiers[3] = MarginAsset.RiskTier({
            maxLeverage: 10,
            maintenanceMarginRatioPpm: 50000,
            positionValueUpperBound: 4000000000000
        });
        ethRiskTiers[4] = MarginAsset.RiskTier({
            maxLeverage: 5,
            maintenanceMarginRatioPpm: 100000,
            positionValueUpperBound: 10000000000000
        });
        ethRiskTiers[5] = MarginAsset.RiskTier({
            maxLeverage: 2,
            maintenanceMarginRatioPpm: 250000,
            positionValueUpperBound: 20000000000000
        });

        ethExchange = MarginAsset.Exchange({
            exchangeId: 200002,
            symbol: "ETHUSDT",
            stepSizeScale: 2,
            tickSizeScale: 2,
            riskTiers: ethRiskTiers
        });

        // 初始化Oracle价格
        oraclePriceMap[200001] = 1000000; // 100,000u (精度6)
        oraclePriceMap[200002] = 300000;  // 3,000u (精度6)

        // 初始化资金费率指数（可为负数，与Go代码保持一致）
        // Go代码中：btcExchange.Id: big.NewInt(-1000000), ethExchange.Id: big.NewInt(-2000000)
        fundingIndexMap[200001] = -1000000; // 精度6
        fundingIndexMap[200002] = -2000000; // 精度6
    }

    /**
     * @notice 测试初始化空资产
     * @dev 对应 Go 测试中的初始状态
     */
    function testNewAssetEmpty() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](2);
        exchanges[0] = btcExchange;
        exchanges[1] = ethExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](2);
        oraclePrices[0] = MarginAsset.OraclePrice({
            exchangeId: 200001,
            oraclePrice: oraclePriceMap[200001],
            oracleTime: 0
        });
        oraclePrices[1] = MarginAsset.OraclePrice({
            exchangeId: 200002,
            oraclePrice: oraclePriceMap[200002],
            oracleTime: 0
        });

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](2);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: fundingIndexMap[200001], fundingIndexTime: 0
        });
        fundingIndices[1] = MarginAsset.FundingIndex({
            exchangeId: 200002,
            fundingIndex: fundingIndexMap[200002], fundingIndexTime: 0
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](2);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 200001,
            leverage: 20,
            marginMode: 1 // MARGIN_MODE_CROSS
        });
        tradeSettings[1] = MarginAsset.TradeSetting({
            exchangeId: 200002,
            leverage: 10,
            marginMode: 1 // MARGIN_MODE_CROSS
        });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 0,
            positions: new MarginAsset.Position[](0)
        });

        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            usdtCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );

        // 验证初始化结果
        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, 0);
        assertEq(asset.crossGroup.tv, 0);
        assertEq(asset.crossGroup.imr, 0);
        assertEq(asset.crossGroup.mmr, 0);
        assertEq(asset.crossGroup.positions.length, 0);
        assertEq(asset.isolatedGroups.length, 0);
    }

    /**
     * @notice 测试带初始抵押品的资产初始化
     * @dev 对应 Go 测试中的 deposit 1000usdt 之后的状态
     */
    function testNewAssetWithInitialCollateral() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](2);
        exchanges[0] = btcExchange;
        exchanges[1] = ethExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](2);
        oraclePrices[0] = MarginAsset.OraclePrice({
            exchangeId: 200001,
            oraclePrice: oraclePriceMap[200001],
            oracleTime: 0
        });
        oraclePrices[1] = MarginAsset.OraclePrice({
            exchangeId: 200002,
            oraclePrice: oraclePriceMap[200002],
            oracleTime: 0
        });

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](2);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: fundingIndexMap[200001], fundingIndexTime: 0
        });
        fundingIndices[1] = MarginAsset.FundingIndex({
            exchangeId: 200002,
            fundingIndex: fundingIndexMap[200002], fundingIndexTime: 0
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](2);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 200001,
            leverage: 20,
            marginMode: 1 // MARGIN_MODE_CROSS
        });
        tradeSettings[1] = MarginAsset.TradeSetting({
            exchangeId: 200002,
            leverage: 10,
            marginMode: 1 // MARGIN_MODE_CROSS
        });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        // 初始抵押品：1000 USDT (精度6)
        int64 crossCollateralAmount = 1000000000; // 1000 * 10^6

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: crossCollateralAmount,
            positions: new MarginAsset.Position[](0)
        });

        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            usdtCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );

        // 验证结果
        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, int256(crossCollateralAmount));
        assertEq(asset.crossGroup.tv, int256(crossCollateralAmount) * int256(PRECISION_SCALE));
        assertEq(asset.crossGroup.imr, 0);
        assertEq(asset.crossGroup.mmr, 0);
        assertEq(asset.crossGroup.positions.length, 0);
        assertEq(asset.isolatedGroups.length, 0);
    }

    /**
     * @notice 测试带仓位的全仓模式资产
     * @dev 对应 Go 测试中买入 0.1btc 之后的状态
     */
    function testNewAssetWithCrossPosition() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] = MarginAsset.OraclePrice({
            exchangeId: 200001,
            oraclePrice: oraclePriceMap[200001],
            oracleTime: 0
        });

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: 0, // 初始资金费率指数为0
            fundingIndexTime: 0
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 200001,
            leverage: 20,
            marginMode: 1 // MARGIN_MODE_CROSS
        });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        // 创建仓位：买入 0.1 BTC
        // openSize: 0.1 BTC = 100 (精度3，即 0.1 * 10^3)
        // openValue: 0.1 * 100050 = 10005 USDT (精度6，即 10005 * 10^6)
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100, // 0.1 BTC
            openValue: 10005000000, // 10005 USDT
            isolatedCollateralAmount: 0,
            cacheFundingIndex: 0 // 初始资金费率指数为0
        });

        // 全仓抵押品：-9006.0005 USDT (精度6，即 -9006000500)
        int64 crossCollateralAmount = -9006000500;

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: crossCollateralAmount,
            positions: positions
        });

        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            usdtCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );

        // 验证结果
        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, int256(crossCollateralAmount));
        
        // TV = collateralAmount * PRECISION_SCALE + PV
        // PV = openSize * oraclePrice = 0.1 * 1000000 = 10000000000000000 (精度6+6=12)
        // TV = -9006000500 * 1000000 + 10000000000000000 = 993999500000000
        int256 expectedTV = int256(crossCollateralAmount) * int256(PRECISION_SCALE) + int256(10000000000000000);
        assertEq(asset.crossGroup.tv, expectedTV);
        
        // 验证仓位信息
        assertEq(asset.crossGroup.positions.length, 1);
        assertEq(asset.crossGroup.positions[0].openSize, 100);
        assertEq(asset.crossGroup.positions[0].openValue, 10005000000);
        assertEq(asset.crossGroup.positions[0].pv, int256(10000000000000000));
        
        // IMR = positionValueAbs * initialMarginRatioPpm
        // positionValue = 0.1 * 1000000 = 100000 (精度6)
        // initialMarginRatioPpm = 1000000 / 20 = 50000
        // IMR = 100000 * 50000 = 500000000000000 (精度6+6=12)
        assertEq(asset.crossGroup.imr, 500000000000000);
        
        // MMR = positionValueAbs * maintenanceMarginRatioPpm
        // positionValue计算：openSize * oraclePrice 做精度转换
        // openSize = 100 (精度3，即0.1 BTC)
        // oraclePrice = 1000000 (精度6，即100000)
        // positionValue = (100 * 1000000) / 10^(3+1-6) = 100000000 / 10^(-2) = 10000000000
        // 实际上应该是：100 * 1000000，然后做精度转换
        // stepSizeScale + tickSizeScale = 3 + 1 = 4
        // coinStepSizeScale = 6
        // 所以需要除以 10^(4-6) = 10^(-2)，即乘以 10^2
        // positionValue = 100 * 1000000 * 100 = 10000000000 (精度6)
        // positionValueAbs = 10000000000
        // 根据风险档位：10000000000 <= 500000000000，使用第一个档位
        // maintenanceMarginRatioPpm = 10000
        // MMR = 10000000000 * 10000 = 100000000000000 (精度12)
        assertEq(asset.crossGroup.mmr, 100000000000000);
        
        assertEq(asset.isolatedGroups.length, 0);
    }

    /**
     * @notice 测试跨仓转出可用金额计算
     */
    function testGetCrossTransferOutAvailableAmount() public {
        // TV = 993999500000000, IMR = 500000000000000, orderFrozenAmount = 0
        int256 tv = 993999500000000;
        uint256 imr = 500000000000000;
        uint256 orderFrozenAmount = 0;
        
        // Create a minimal CrossGroup for testing
        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: 0,
            positions: new MarginAsset.AssetPosition[](0),
            imr: imr,
            mmr: 0,
            tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(
            tv,
            imr,
            orderFrozenAmount,
            crossGroup
        );

        // availableAmount = (TV - IMR - orderFrozenAmount) / PRECISION_SCALE
        // = (993999500000000 - 500000000000000 - 0) / 1000000
        // = 493999500000000 / 1000000
        // = 493999500
        // 但根据精度，应该是 493.9995，即 493999500 (精度6)
        assertEq(uint256(availableAmount), 493999500);
    }

    /**
     * @notice 测试跨仓转出可用金额计算（负数TV情况）
     */
    function testGetCrossTransferOutAvailableAmountNegativeTV() public {
        int256 tv = -1000000000000; // -1 USDT (精度12)
        uint256 imr = 500000000000000;
        uint256 orderFrozenAmount = 0;
        
        // Create a minimal CrossGroup for testing
        MarginAsset.CrossGroup memory crossGroup = MarginAsset.CrossGroup({
            collateralAmount: 0,
            positions: new MarginAsset.AssetPosition[](0),
            imr: imr,
            mmr: 0,
            tv: tv
        });

        int256 availableAmount = MarginAsset.getCrossTransferOutAvailableAmount(
            tv,
            imr,
            orderFrozenAmount,
            crossGroup
        );

        // TV < IMR + orderFrozenAmount，应该返回0
        assertEq(availableAmount, 0);
    }

    /**
     * @notice 测试带逐仓仓位的资产
     * @dev 对应 Go 测试中的逐仓模式
     */
    function testNewAssetWithIsolatedPosition() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] = MarginAsset.OraclePrice({
            exchangeId: 200001,
            oraclePrice: oraclePriceMap[200001],
            oracleTime: 0
        });

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: 0, fundingIndexTime: 0
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 200001,
            leverage: 20,
            marginMode: 2 // MARGIN_MODE_ISOLATED
        });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        // 创建逐仓仓位：买入 0.1 BTC
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100, // 0.1 BTC
            openValue: 10005000000, // 10005 USDT
            isolatedCollateralAmount: -9505000000, // 逐仓抵押品（精度6）
            cacheFundingIndex: 0 // 初始资金费率指数为0
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 498999500, // 全仓剩余抵押品（精度6）
            positions: positions
        });

        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            usdtCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );

        // 验证结果
        assertEq(asset.subaccountId, 123);
        assertEq(asset.collateralCoinId, 1000);
        assertEq(asset.crossGroup.collateralAmount, 498999500);
        assertEq(asset.isolatedGroups.length, 1);
        assertEq(asset.isolatedGroups[0].collateralAmount, int256(-9505000000));
        assertEq(asset.isolatedGroups[0].position.openSize, 100);
        assertEq(asset.isolatedGroups[0].position.openValue, 10005000000);
    }

    /**
     * @notice 测试负数 fundingIndex 的情况
     * @dev 测试资金费率指数为负数时的资金费用计算
     */
    function testNewAssetWithNegativeFundingIndex() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] = MarginAsset.OraclePrice({
            exchangeId: 200001,
            oraclePrice: oraclePriceMap[200001],
            oracleTime: 0
        });

        // 使用负数 fundingIndex（与 Go 测试保持一致）
        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: fundingIndexMap[200001], fundingIndexTime: 0 // -1000000
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 200001,
            leverage: 20,
            marginMode: 1 // MARGIN_MODE_CROSS
        });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        // 创建仓位，cacheFundingIndex 为 0，fundingIndex 为 -1000000
        // 资金费用 = openSize * (cacheFundingIndex - fundingIndex) = 100 * (0 - (-1000000)) = 100000000
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100, // 0.1 BTC
            openValue: 10005000000, // 10005 USDT
            isolatedCollateralAmount: 0,
            cacheFundingIndex: 0 // 初始资金费率指数为0
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 0,
            positions: positions
        });

        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            usdtCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );

        // 验证资金费用已正确计算并添加到全仓抵押品中
        // 资金费用应该是正数（因为 cacheFundingIndex > fundingIndex）
        assertGt(asset.crossGroup.collateralAmount, 0);
    }

    /**
     * @notice 测试负数 cacheFundingIndex 的情况
     * @dev 测试缓存的资金费率指数为负数时的资金费用计算
     */
    function testNewAssetWithNegativeCacheFundingIndex() public {
        MarginAsset.Exchange[] memory exchanges = new MarginAsset.Exchange[](1);
        exchanges[0] = btcExchange;

        MarginAsset.OraclePrice[] memory oraclePrices = new MarginAsset.OraclePrice[](1);
        oraclePrices[0] = MarginAsset.OraclePrice({
            exchangeId: 200001,
            oraclePrice: oraclePriceMap[200001],
            oracleTime: 0
        });

        MarginAsset.FundingIndex[] memory fundingIndices = new MarginAsset.FundingIndex[](1);
        fundingIndices[0] = MarginAsset.FundingIndex({
            exchangeId: 200001,
            fundingIndex: 0, fundingIndexTime: 0
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: 200001,
            leverage: 20,
            marginMode: 1 // MARGIN_MODE_CROSS
        });

        MarginAsset.Subaccount memory subaccount = MarginAsset.Subaccount({
            id: 123,
            chainAddress: bytes32(0),
            clientAccountId: "test",
            tradeSettings: tradeSettings
        });

        // 创建仓位，cacheFundingIndex 为负数
        MarginAsset.Position[] memory positions = new MarginAsset.Position[](1);
        positions[0] = MarginAsset.Position({
            exchangeId: 200001,
            openSize: 100, // 0.1 BTC
            openValue: 10005000000, // 10005 USDT
            isolatedCollateralAmount: 0,
            cacheFundingIndex: -1000000 // 负数资金费率指数
        });

        MarginAsset.PerpetualAsset memory perpetualAsset = MarginAsset.PerpetualAsset({
            subaccountId: 123,
            collateralCoinId: 1000,
            crossCollateralAmount: 1000000000, // 1000 USDT
            positions: positions
        });

        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            usdtCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );

        // 验证资金费用已正确计算（cacheFundingIndex - fundingIndex = -1000000 - 0 = -1000000）
        // 对于多仓（openSize > 0），负的资金费用会减少抵押品
        assertLt(asset.crossGroup.collateralAmount, int256(1000000000));
    }

    /**
     * @notice 辅助函数：精度转换
     */
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
}

