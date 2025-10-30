// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {MarginAsset, MarginAssetCalculator} from "./MarginAsset.sol";

/**
 * @title MarginAssetTest
 * @notice 测试MarginAsset合约的getCrossTransferOutAvailableAmount功能
 */
contract MarginAssetTest is Test {
    using MarginAsset for MarginAsset.Asset;

    MarginAssetCalculator public calculator;

    // 测试数据常量
    uint64 constant BTC_EXCHANGE_ID = 200001;
    uint64 constant ETH_EXCHANGE_ID = 200002;
    uint64 constant USDT_COIN_ID = 1000;
    uint32 constant USDT_STEP_SIZE_SCALE = 6;
    uint32 constant BTC_STEP_SIZE_SCALE = 3;
    uint32 constant ETH_STEP_SIZE_SCALE = 2;
    uint32 constant BTC_TICK_SIZE_SCALE = 1;
    uint32 constant ETH_TICK_SIZE_SCALE = 2;

    // Oracle价格（精度为TickSizeScale）
    uint256 constant BTC_ORACLE_PRICE = 1000000; // 100,000u
    uint256 constant ETH_ORACLE_PRICE = 300000;  // 3,000u

    // 资金费率指数
    uint256 constant BTC_FUNDING_INDEX = 0;
    uint256 constant ETH_FUNDING_INDEX = 0;

    function setUp() public {
        calculator = new MarginAssetCalculator();
    }

    /**
     * @notice 测试场景1：初始状态，无仓位，无订单冻结
     * 对应Go测试：TestMarginAssetCross初始状态后deposit 1000usdt
     */
    function testGetCrossTransferOutAvailableAmount_InitialState() public view  {
        // 初始状态：deposit 1000 USDT
        int64 crossCollateralAmount = 1000 * 10**6; // 1000 USDT，精度为6
        uint256 orderFrozenAmount = 0;

        MarginAsset.PositionInput[] memory positions = new MarginAsset.PositionInput[](0);
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](0);
        MarginAsset.ExchangeInfo[] memory exchanges = new MarginAsset.ExchangeInfo[](0);

        uint256 availableAmount = calculator.getCrossTransferOutAvailableAmount(
            crossCollateralAmount,
            USDT_STEP_SIZE_SCALE,
            orderFrozenAmount,
            positions,
            tradeSettings,
            exchanges
        );

        // TV = 1000 * 10^6 = 1000000000000
        // IMR = 0
        // orderFrozenAmount = 0
        // availableAmount = (1000000000000 - 0 - 0) / 1000000 = 1000000000
        // 但由于精度转换，实际应该是1000 (USDT精度为6)
        // 在内部计算中，TV是精度为6+6=12的量，所以结果是1000000000000 / 1000000 = 1000000 (精度6)
        // 但等等，CrossCollateralAmount的精度是6，乘以1000000后TV精度是12
        // 所以availableAmount应该是 (1000000000000 - 0 - 0) / 1000000 = 1000000 (精度6)，即1000 USDT
        assertEq(availableAmount, 1000 * 10**6);
    }

    /**
     * @notice 测试场景2：有仓位，无订单冻结
     * 对应Go测试：TestMarginAssetCross中buy 0.1btc后的状态
     * TV = 993999500000000 (精度12)
     * IMR = 500000000000000 (精度12)
     * availableAmount = (993999500000000 - 500000000000000) / 1000000 = 493999500 (精度6)
     */
    function testGetCrossTransferOutAvailableAmount_WithPosition() public  view {
        // 初始抵押品：-9006.0005 USDT (精度6)
        int64 crossCollateralAmount = -9006000500;
        
        // 构建仓位
        MarginAsset.PositionInput[] memory positions = new MarginAsset.PositionInput[](1);
        positions[0] = MarginAsset.PositionInput({
            exchangeId: BTC_EXCHANGE_ID,
            openSize: 100, // 0.1 BTC
            openValue: 10005000000, // 10005 USDT
            isolatedCollateralAmount: 0,
            cacheFundingIndex: BTC_FUNDING_INDEX
        });

        // 构建交易设置
        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: BTC_EXCHANGE_ID,
            leverage: 20,
            marginMode: 1 // 全仓模式
        });

        // 构建交易所信息
        MarginAsset.ExchangeInfo[] memory exchanges = new MarginAsset.ExchangeInfo[](1);
        exchanges[0] = MarginAsset.ExchangeInfo({
            exchangeId: BTC_EXCHANGE_ID,
            stepSizeScale: BTC_STEP_SIZE_SCALE,
            tickSizeScale: BTC_TICK_SIZE_SCALE,
            oraclePrice: BTC_ORACLE_PRICE,
            fundingIndex: BTC_FUNDING_INDEX,
            riskTiers: createBTCRiskTiers()
        });

        uint256 orderFrozenAmount = 0;

        uint256 availableAmount = calculator.getCrossTransferOutAvailableAmount(
            crossCollateralAmount,
            USDT_STEP_SIZE_SCALE,
            orderFrozenAmount,
            positions,
            tradeSettings,
            exchanges
        );

        // TV = 993999500000000 (精度12)
        // IMR = 500000000000000 (精度12)
        // availableAmount = (993999500000000 - 500000000000000) / 1000000 = 493999500 (精度6)
        assertEq(availableAmount, 493999500);
    }

    /**
     * @notice 测试场景3：有仓位，有订单冻结
     */
    function testGetCrossTransferOutAvailableAmount_WithPositionAndOrderFrozen() public  view {
        int64 crossCollateralAmount = -9006000500;
        
        MarginAsset.PositionInput[] memory positions = new MarginAsset.PositionInput[](1);
        positions[0] = MarginAsset.PositionInput({
            exchangeId: BTC_EXCHANGE_ID,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: BTC_FUNDING_INDEX
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: BTC_EXCHANGE_ID,
            leverage: 20,
            marginMode: 1
        });

        MarginAsset.ExchangeInfo[] memory exchanges = new MarginAsset.ExchangeInfo[](1);
        exchanges[0] = MarginAsset.ExchangeInfo({
            exchangeId: BTC_EXCHANGE_ID,
            stepSizeScale: BTC_STEP_SIZE_SCALE,
            tickSizeScale: BTC_TICK_SIZE_SCALE,
            oraclePrice: BTC_ORACLE_PRICE,
            fundingIndex: BTC_FUNDING_INDEX,
            riskTiers: createBTCRiskTiers()
        });

        // 订单冻结100 USDT (精度12)
        uint256 orderFrozenAmount = 100 * 10**12;

        uint256 availableAmount = calculator.getCrossTransferOutAvailableAmount(
            crossCollateralAmount,
            USDT_STEP_SIZE_SCALE,
            orderFrozenAmount,
            positions,
            tradeSettings,
            exchanges
        );

        // TV = 993999500000000 (精度12)
        // IMR = 500000000000000 (精度12)
        // orderFrozenAmount = 100000000000000 (精度12)
        // availableAmount = (993999500000000 - 500000000000000 - 100000000000000) / 1000000 = 393999500 (精度6)
        assertEq(availableAmount, 393999500);
    }

    /**
     * @notice 测试场景4：可用金额不足的情况（返回0）
     */
    function testGetCrossTransferOutAvailableAmount_Insufficient() public  view {
        int64 crossCollateralAmount = -9006000500;
        
        MarginAsset.PositionInput[] memory positions = new MarginAsset.PositionInput[](1);
        positions[0] = MarginAsset.PositionInput({
            exchangeId: BTC_EXCHANGE_ID,
            openSize: 100,
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: BTC_FUNDING_INDEX
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: BTC_EXCHANGE_ID,
            leverage: 20,
            marginMode: 1
        });

        MarginAsset.ExchangeInfo[] memory exchanges = new MarginAsset.ExchangeInfo[](1);
        exchanges[0] = MarginAsset.ExchangeInfo({
            exchangeId: BTC_EXCHANGE_ID,
            stepSizeScale: BTC_STEP_SIZE_SCALE,
            tickSizeScale: BTC_TICK_SIZE_SCALE,
            oraclePrice: BTC_ORACLE_PRICE,
            fundingIndex: BTC_FUNDING_INDEX,
            riskTiers: createBTCRiskTiers()
        });

        // 订单冻结金额非常大，超过可用金额
        uint256 orderFrozenAmount = 500 * 10**12; // 500 USDT (精度12)

        uint256 availableAmount = calculator.getCrossTransferOutAvailableAmount(
            crossCollateralAmount,
            USDT_STEP_SIZE_SCALE,
            orderFrozenAmount,
            positions,
            tradeSettings,
            exchanges
        );

        // TV = 993999500000000 (精度12)
        // IMR = 500000000000000 (精度12)
        // orderFrozenAmount = 500000000000000 (精度12)
        // TV - IMR - orderFrozenAmount = 993999500000000 - 500000000000000 - 500000000000000 = -6000500000 < 0
        // availableAmount = 0
        assertEq(availableAmount, 0);
    }

    /**
     * @notice 测试场景5：空仓位状态（卖空后）
     * 对应Go测试：TestMarginAssetCross中sell 0.15btc后的状态
     */
    function testGetCrossTransferOutAvailableAmount_ShortPosition() public  view {
        // 卖空后的状态：CollateralAmount = 5977501000 (精度6)
        int64 crossCollateralAmount = 5977501000;
        
        MarginAsset.PositionInput[] memory positions = new MarginAsset.PositionInput[](1);
        positions[0] = MarginAsset.PositionInput({
            exchangeId: BTC_EXCHANGE_ID,
            openSize: -50, // -0.05 BTC (空仓)
            openValue: -4995000000, // -4995 USDT
            isolatedCollateralAmount: 0,
            cacheFundingIndex: BTC_FUNDING_INDEX
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: BTC_EXCHANGE_ID,
            leverage: 20,
            marginMode: 1
        });

        MarginAsset.ExchangeInfo[] memory exchanges = new MarginAsset.ExchangeInfo[](1);
        exchanges[0] = MarginAsset.ExchangeInfo({
            exchangeId: BTC_EXCHANGE_ID,
            stepSizeScale: BTC_STEP_SIZE_SCALE,
            tickSizeScale: BTC_TICK_SIZE_SCALE,
            oraclePrice: BTC_ORACLE_PRICE,
            fundingIndex: BTC_FUNDING_INDEX,
            riskTiers: createBTCRiskTiers()
        });

        uint256 orderFrozenAmount = 0;

        uint256 availableAmount = calculator.getCrossTransferOutAvailableAmount(
            crossCollateralAmount,
            USDT_STEP_SIZE_SCALE,
            orderFrozenAmount,
            positions,
            tradeSettings,
            exchanges
        );

        // TV = 977501000000000 (精度12)
        // IMR = 250000000000000 (精度12)
        // availableAmount = (977501000000000 - 250000000000000) / 1000000 = 727501000 (精度6)
        assertEq(availableAmount, 727501000);
    }

    /**
     * @notice 测试场景6：多个仓位
     */
    function testGetCrossTransferOutAvailableAmount_MultiplePositions() public  view {
        int64 crossCollateralAmount = 1000 * 10**6;
        
        MarginAsset.PositionInput[] memory positions = new MarginAsset.PositionInput[](2);
        positions[0] = MarginAsset.PositionInput({
            exchangeId: BTC_EXCHANGE_ID,
            openSize: 100, // 0.1 BTC
            openValue: 10005000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: BTC_FUNDING_INDEX
        });
        positions[1] = MarginAsset.PositionInput({
            exchangeId: ETH_EXCHANGE_ID,
            openSize: 1000, // 10 ETH
            openValue: 3000000000,
            isolatedCollateralAmount: 0,
            cacheFundingIndex: ETH_FUNDING_INDEX
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](2);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: BTC_EXCHANGE_ID,
            leverage: 20,
            marginMode: 1
        });
        tradeSettings[1] = MarginAsset.TradeSetting({
            exchangeId: ETH_EXCHANGE_ID,
            leverage: 10,
            marginMode: 1
        });

        MarginAsset.ExchangeInfo[] memory exchanges = new MarginAsset.ExchangeInfo[](2);
        exchanges[0] = MarginAsset.ExchangeInfo({
            exchangeId: BTC_EXCHANGE_ID,
            stepSizeScale: BTC_STEP_SIZE_SCALE,
            tickSizeScale: BTC_TICK_SIZE_SCALE,
            oraclePrice: BTC_ORACLE_PRICE,
            fundingIndex: BTC_FUNDING_INDEX,
            riskTiers: createBTCRiskTiers()
        });
        exchanges[1] = MarginAsset.ExchangeInfo({
            exchangeId: ETH_EXCHANGE_ID,
            stepSizeScale: ETH_STEP_SIZE_SCALE,
            tickSizeScale: ETH_TICK_SIZE_SCALE,
            oraclePrice: ETH_ORACLE_PRICE,
            fundingIndex: ETH_FUNDING_INDEX,
            riskTiers: createETHRiskTiers()
        });

        uint256 orderFrozenAmount = 0;

        uint256 availableAmount = calculator.getCrossTransferOutAvailableAmount(
            crossCollateralAmount,
            USDT_STEP_SIZE_SCALE,
            orderFrozenAmount,
            positions,
            tradeSettings,
            exchanges
        );

        // 应该能够正常计算，不会revert
        assertGe(availableAmount, 0);
    }

    /**
     * @notice 测试场景7：逐仓模式仓位（不应该影响CrossGroup的可用金额）
     */
    function testGetCrossTransferOutAvailableAmount_IsolatedPosition() public  view {
        int64 crossCollateralAmount = 1000 * 10**6;
        
        MarginAsset.PositionInput[] memory positions = new MarginAsset.PositionInput[](1);
        positions[0] = MarginAsset.PositionInput({
            exchangeId: BTC_EXCHANGE_ID,
            openSize: 100, // 0.1 BTC
            openValue: 10005000000,
            isolatedCollateralAmount: 500 * 10**6, // 500 USDT逐仓抵押品
            cacheFundingIndex: BTC_FUNDING_INDEX
        });

        MarginAsset.TradeSetting[] memory tradeSettings = new MarginAsset.TradeSetting[](1);
        tradeSettings[0] = MarginAsset.TradeSetting({
            exchangeId: BTC_EXCHANGE_ID,
            leverage: 20,
            marginMode: 2 // 逐仓模式
        });

        MarginAsset.ExchangeInfo[] memory exchanges = new MarginAsset.ExchangeInfo[](1);
        exchanges[0] = MarginAsset.ExchangeInfo({
            exchangeId: BTC_EXCHANGE_ID,
            stepSizeScale: BTC_STEP_SIZE_SCALE,
            tickSizeScale: BTC_TICK_SIZE_SCALE,
            oraclePrice: BTC_ORACLE_PRICE,
            fundingIndex: BTC_FUNDING_INDEX,
            riskTiers: createBTCRiskTiers()
        });

        uint256 orderFrozenAmount = 0;

        uint256 availableAmount = calculator.getCrossTransferOutAvailableAmount(
            crossCollateralAmount,
            USDT_STEP_SIZE_SCALE,
            orderFrozenAmount,
            positions,
            tradeSettings,
            exchanges
        );

        // 逐仓模式仓位不应该影响CrossGroup的TV和IMR
        // TV = 1000 * 10^12 = 1000000000000000
        // IMR = 0
        // availableAmount = 1000000000000000 / 1000000 = 1000000000 (精度6)
        assertEq(availableAmount, 1000 * 10**6);
    }

    /**
     * @notice 创建BTC风险档位
     */
    function createBTCRiskTiers() internal pure returns (MarginAsset.RiskTier[] memory) {
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](6);
        riskTiers[0] = MarginAsset.RiskTier({
            maxLeverage: 50,
            maintenanceMarginRatioPpm: 10000,
            positionValueUpperBound: 500000000000
        });
        riskTiers[1] = MarginAsset.RiskTier({
            maxLeverage: 25,
            maintenanceMarginRatioPpm: 20000,
            positionValueUpperBound: 1000000000000
        });
        riskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 20,
            maintenanceMarginRatioPpm: 25000,
            positionValueUpperBound: 2000000000000
        });
        riskTiers[3] = MarginAsset.RiskTier({
            maxLeverage: 10,
            maintenanceMarginRatioPpm: 50000,
            positionValueUpperBound: 4000000000000
        });
        riskTiers[4] = MarginAsset.RiskTier({
            maxLeverage: 5,
            maintenanceMarginRatioPpm: 100000,
            positionValueUpperBound: 10000000000000
        });
        riskTiers[5] = MarginAsset.RiskTier({
            maxLeverage: 2,
            maintenanceMarginRatioPpm: 250000,
            positionValueUpperBound: 20000000000000
        });
        return riskTiers;
    }

    /**
     * @notice 创建ETH风险档位
     */
    function createETHRiskTiers() internal pure returns (MarginAsset.RiskTier[] memory) {
        MarginAsset.RiskTier[] memory riskTiers = new MarginAsset.RiskTier[](6);
        riskTiers[0] = MarginAsset.RiskTier({
            maxLeverage: 50,
            maintenanceMarginRatioPpm: 10000,
            positionValueUpperBound: 500000000000
        });
        riskTiers[1] = MarginAsset.RiskTier({
            maxLeverage: 25,
            maintenanceMarginRatioPpm: 20000,
            positionValueUpperBound: 1000000000000
        });
        riskTiers[2] = MarginAsset.RiskTier({
            maxLeverage: 20,
            maintenanceMarginRatioPpm: 25000,
            positionValueUpperBound: 2000000000000
        });
        riskTiers[3] = MarginAsset.RiskTier({
            maxLeverage: 10,
            maintenanceMarginRatioPpm: 50000,
            positionValueUpperBound: 4000000000000
        });
        riskTiers[4] = MarginAsset.RiskTier({
            maxLeverage: 5,
            maintenanceMarginRatioPpm: 100000,
            positionValueUpperBound: 10000000000000
        });
        riskTiers[5] = MarginAsset.RiskTier({
            maxLeverage: 2,
            maintenanceMarginRatioPpm: 250000,
            positionValueUpperBound: 20000000000000
        });
        return riskTiers;
    }
}

