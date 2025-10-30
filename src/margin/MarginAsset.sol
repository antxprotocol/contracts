// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title MarginAsset
 * @notice 实现保证金资产相关计算，包括跨仓转出可用金额计算
 * @dev 完整实现了NewAsset的逻辑，能够从原始数据构造Asset对象并计算可用金额
 */
library MarginAsset {
    // 精度常量：1000000 (6位小数)
    uint256 private constant PRECISION_SCALE = 1000000;

    // 仓位信息结构体
    struct Position {
        int256 openSize;   // 开仓仓位大小，多仓为正数，空仓为负数
        int256 openValue;  // 开仓价值，多仓为正数，空仓为负数
        uint256 imr;       // 初始保证金需求，精度为 collateralCoin.StepSizeScale + 6
        uint256 mmr;       // 维持保证金需求，精度为 collateralCoin.StepSizeScale + 6
        uint256 pv;        // 仓位价值，精度为 collateralCoin.StepSizeScale + 6
    }

    // 全仓组结构体
    struct CrossGroup {
        uint256 collateralAmount; // 全仓模式抵押品数量，精度为 collateralCoin.StepSizeScale
        uint256 imr;              // 初始保证金需求，精度为 collateralCoin.StepSizeScale + 6
        uint256 mmr;              // 维持保证金需求，精度为 collateralCoin.StepSizeScale + 6
        uint256 tv;                // 总价值，精度为 collateralCoin.StepSizeScale + 6
    }

    // 逐仓组结构体
    struct IsolatedGroup {
        uint256 collateralAmount; // 逐仓模式抵押品数量，精度为 collateralCoin.StepSizeScale
        Position position;        // 仓位信息
        uint256 tv;               // 总价值，精度为 collateralCoin.StepSizeScale + 6
    }

    // Asset结构体（完整版本）
    struct Asset {
        CrossGroup crossGroup;                    // 全仓组
        IsolatedGroup[] isolatedGroups;          // 逐仓组列表（使用数组代替map）
        uint64[] isolatedGroupExchangeIds;       // 对应的交易所ID列表，用于快速查找
    }

    // 风险档位结构体
    struct RiskTier {
        uint32 maxLeverage;                  // 最大杠杆
        uint32 maintenanceMarginRatioPpm;    // 维持保证金率，单位：百万分之一
        uint64 positionValueUpperBound;      // 最大持仓价值
    }

    // 交易设置结构体
    struct TradeSetting {
        uint64 exchangeId;  // 交易所ID
        uint32 leverage;   // 杠杆倍数
        uint8 marginMode;  // 保证金模式：1=全仓，2=逐仓
    }

    // 仓位输入结构体
    struct PositionInput {
        uint64 exchangeId;               // 交易所ID
        int64 openSize;                  // 开仓仓位大小
        int64 openValue;                 // 开仓价值
        int64 isolatedCollateralAmount;  // 逐仓抵押品数量（仅逐仓模式有效）
        uint256 cacheFundingIndex;       // 缓存的资金费率指数
    }

    // 交易所信息结构体
    struct ExchangeInfo {
        uint64 exchangeId;              // 交易所ID
        uint32 stepSizeScale;           // 步长精度
        uint32 tickSizeScale;           // 价格精度
        uint256 oraclePrice;            // Oracle价格
        uint256 fundingIndex;           // 资金费率指数
        RiskTier[] riskTiers;           // 风险档位列表
    }

    /**
     * @notice 计算跨仓转出可用金额
     * @dev 计算公式: availableAmount = (TV - IMR - orderFrozenAmount) / PRECISION_SCALE
     *      如果计算结果小于0，返回0
     *      
     * @param tv 总价值 (Total Value)，精度为 collateralCoin.StepSizeScale + 6
     * @param imr 初始保证金需求 (Initial Margin Requirement)，精度为 collateralCoin.StepSizeScale + 6
     * @param orderFrozenAmount 订单冻结金额，精度为 collateralCoin.StepSizeScale + 6
     * @return availableAmount 可用金额，精度为 collateralCoin.StepSizeScale
     */
    function getCrossTransferOutAvailableAmount(
        uint256 tv,
        uint256 imr,
        uint256 orderFrozenAmount
    ) internal pure returns (uint256 availableAmount) {
        // 检查是否会下溢: 如果 TV < IMR + orderFrozenAmount，返回0
        // 先检查imr + orderFrozenAmount是否溢出，如果溢出则直接返回0
        if (imr > type(uint256).max - orderFrozenAmount) {
            return 0;
        }
        
        // 检查是否会下溢: 如果 TV < IMR + orderFrozenAmount，返回0
        if (tv < imr + orderFrozenAmount) {
            return 0;
        }
        
        // 计算: (TV - IMR - orderFrozenAmount) / PRECISION_SCALE
        unchecked {
            availableAmount = (tv - imr - orderFrozenAmount) / PRECISION_SCALE;
        }
        
        return availableAmount;
    }

    /**
     * @notice 从杠杆倍数计算初始保证金率（单位：百万分之一）
     * @param leverage 杠杆倍数
     * @return initialMarginRatioPpm 初始保证金率（单位：百万分之一）
     */
    function leverageToInitialMarginRatioPpm(
        uint32 leverage
    ) internal pure returns (uint32 initialMarginRatioPpm) {
        require(leverage > 0, "leverage must be greater than 0");
        return uint32(PRECISION_SCALE / uint256(leverage));
    }

    /**
     * @notice 计算仓位价值
     * @dev 计算公式: positionValue = (openSize * oraclePrice) / (10^(stepSizeScale + tickSizeScale - coinStepSizeScale))
     * @param openSize 开仓大小（带符号）
     * @param oraclePrice Oracle价格
     * @param stepSizeScale 步长精度
     * @param tickSizeScale 价格精度
     * @param coinStepSizeScale 币种步长精度
     * @return positionValue 仓位价值（带符号），精度为 coinStepSizeScale
     */
    function calculatePositionValue(
        int256 openSize,
        uint256 oraclePrice,
        uint32 stepSizeScale,
        uint32 tickSizeScale,
        uint32 coinStepSizeScale
    ) internal pure returns (int256 positionValue) {
        // 计算 (openSize * oraclePrice) / 10^(stepSizeScale + tickSizeScale - coinStepSizeScale)
        uint256 absOpenSize = absInt(openSize);
        uint256 value = absOpenSize * oraclePrice;
        
        uint32 scaleDiff = stepSizeScale + tickSizeScale;
        if (scaleDiff > coinStepSizeScale) {
            uint32 divisor = scaleDiff - coinStepSizeScale;
            value = value / (10 ** divisor);
        } else if (scaleDiff < coinStepSizeScale) {
            uint32 multiplier = coinStepSizeScale - scaleDiff;
            value = value * (10 ** multiplier);
        }
        
        return openSize < 0 ? -int256(value) : int256(value);
    }

    /**
     * @notice 计算仓位绝对价值
     */
    function absInt(int256 x) private pure returns (uint256) {
        return x < 0 ? uint256(-x) : uint256(x);
    }

    /**
     * @notice 计算仓位初始保证金额
     * @param positionValueAbs 仓位绝对价值，精度为 collateralCoin.StepSizeScale
     * @param initialMarginRatioPpm 初始保证金率（单位：百万分之一）
     * @return imr 初始保证金额，精度为 collateralCoin.StepSizeScale + 6
     */
    function calculatePositionIMR(
        uint256 positionValueAbs,
        uint32 initialMarginRatioPpm
    ) internal pure returns (uint256 imr) {
        return (positionValueAbs * uint256(initialMarginRatioPpm));
    }

    /**
     * @notice 计算仓位维持保证金额
     * @param positionValueAbs 仓位绝对价值，精度为 collateralCoin.StepSizeScale
     * @param maintenanceMarginRatioPpm 维持保证金率（单位：百万分之一）
     * @return mmr 维持保证金额，精度为 collateralCoin.StepSizeScale + 6
     */
    function calculatePositionMMR(
        uint256 positionValueAbs,
        uint32 maintenanceMarginRatioPpm
    ) internal pure returns (uint256 mmr) {
        return (positionValueAbs * uint256(maintenanceMarginRatioPpm));
    }

    /**
     * @notice 根据仓位价值查找对应的风险档位
     * @param riskTiers 风险档位列表（必须按照positionValueUpperBound从小到大排列）
     * @param positionValueAbs 仓位绝对价值
     * @return riskTierIndex 找到的风险档位索引，如果没找到返回最后一个档位
     */
    function findPositionRiskTier(
        RiskTier[] memory riskTiers,
        uint256 positionValueAbs
    ) internal pure returns (uint256 riskTierIndex) {
        require(riskTiers.length > 0, "risk tiers is empty");
        
        // 遍历查找匹配的风险档位
        for (uint256 i = 0; i < riskTiers.length; i++) {
            uint256 upperBound = uint256(riskTiers[i].positionValueUpperBound);
            if (positionValueAbs <= upperBound) {
                return i;
            }
        }
        
        // 没找到，返回最后一个档位（兜底）
        return riskTiers.length - 1;
    }

    /**
     * @notice 计算最小值的辅助函数
     */
    function min(uint32 a, uint32 b) private pure returns (uint32) {
        return a < b ? a : b;
    }

    /**
     * @notice 计算资金费用
     * @dev fundingAmount = openSize * (cacheFundingIndex - fundingIndex)
     *      然后需要做精度转换从 (stepSizeScale + tickSizeScale + 6) 到 (coinStepSizeScale + 6)
     */
    function calculateFundingAmount(
        int256 openSize,
        uint256 cacheFundingIndex,
        uint256 fundingIndex,
        uint32 stepSizeScale,
        uint32 tickSizeScale,
        uint32 coinStepSizeScale
    ) internal pure returns (int256 fundingAmount) {
        // 计算资金费率差值
        int256 fundingDiff;
        if (cacheFundingIndex >= fundingIndex) {
            fundingDiff = int256(cacheFundingIndex - fundingIndex);
        } else {
            fundingDiff = -int256(fundingIndex - cacheFundingIndex);
        }
        
        // fundingAmount = openSize * fundingDiff
        // 精度转换从 (stepSizeScale + tickSizeScale + 6) 到 (coinStepSizeScale + 6)
        uint256 absOpenSize = absInt(openSize);
        uint256 absFundingDiff = absInt(fundingDiff);
        
        uint256 value = absOpenSize * absFundingDiff;
        
        uint32 scaleDiff = stepSizeScale + tickSizeScale + 6;
        uint32 targetScale = coinStepSizeScale + 6;
        if (scaleDiff > targetScale) {
            uint32 divisor = scaleDiff - targetScale;
            value = value / (10 ** divisor);
        } else if (scaleDiff < targetScale) {
            uint32 multiplier = targetScale - scaleDiff;
            value = value * (10 ** multiplier);
        }
        
        bool isNegative = (openSize < 0) != (fundingDiff < 0);
        return isNegative ? -int256(value) : int256(value);
    }

    /**
     * @notice 新建Asset对象（从原始数据计算）
     * @param crossCollateralAmount 全仓抵押品数量，精度为 collateralCoin.StepSizeScale
     * @param coinStepSizeScale 币种步长精度
     * @param positions 仓位列表
     * @param tradeSettings 交易设置列表
     * @param exchanges 交易所信息列表
     * @return asset 完整的Asset对象，包含CrossGroup和IsolatedGroup数组
     */
    function newAsset(
        int256 crossCollateralAmount,
        uint32 coinStepSizeScale,
        PositionInput[] memory positions,
        TradeSetting[] memory tradeSettings,
        ExchangeInfo[] memory exchanges
    ) internal pure returns (Asset memory asset) {
        // 初始化CrossGroup
        // 处理负数：如果collateralAmount为负，collateralAmountUint存储绝对值，但TV需要正确计算
        uint256 collateralAmountUint = absInt(crossCollateralAmount);
        asset.crossGroup.collateralAmount = collateralAmountUint;
        
        // TV = collateralAmount * PRECISION_SCALE，如果collateralAmount为负，则TV从0开始
        // 但是当添加positionPV时，需要减去负数的绝对值
        bool isCollateralNegative = crossCollateralAmount < 0;
        if (crossCollateralAmount >= 0) {
            asset.crossGroup.tv = collateralAmountUint * PRECISION_SCALE;
        } else {
            // 如果collateralAmount为负，TV从0开始
            // 后续添加positionPV时需要减去abs(collateralAmount) * PRECISION_SCALE
            asset.crossGroup.tv = 0;
        }
        asset.crossGroup.imr = 0;
        asset.crossGroup.mmr = 0;

        // 初始化IsolatedGroup数组（预留空间）
        IsolatedGroup[] memory isolatedGroups = new IsolatedGroup[](positions.length);
        uint64[] memory isolatedGroupExchangeIds = new uint64[](positions.length);
        uint256 isolatedGroupCount = 0;

        int256 crossFundingAmount = 0; // 精度为 collateralCoin.StepSizeScale + 6
        uint256 negativeCollateralAdjustment = isCollateralNegative ? collateralAmountUint * PRECISION_SCALE : 0;

        // 遍历所有仓位
        for (uint256 i = 0; i < positions.length; i++) {
            PositionInput memory positionInput = positions[i];
            
            // 查找对应的exchange和tradeSetting
            ExchangeInfo memory exchange;
            bool exchangeFound = false;
            TradeSetting memory tradeSetting;
            bool tradeSettingFound = false;
            
            for (uint256 j = 0; j < exchanges.length; j++) {
                if (exchanges[j].exchangeId == positionInput.exchangeId) {
                    exchange = exchanges[j];
                    exchangeFound = true;
                    break;
                }
            }
            
            for (uint256 j = 0; j < tradeSettings.length; j++) {
                if (tradeSettings[j].exchangeId == positionInput.exchangeId) {
                    tradeSetting = tradeSettings[j];
                    tradeSettingFound = true;
                    break;
                }
            }
            
            require(exchangeFound, "exchange not found");
            require(tradeSettingFound && tradeSetting.leverage > 0, "trade setting not valid");

            // 计算资金费用
            int256 fundingAmount = calculateFundingAmount(
                int256(positionInput.openSize),
                positionInput.cacheFundingIndex,
                exchange.fundingIndex,
                exchange.stepSizeScale,
                exchange.tickSizeScale,
                coinStepSizeScale
            );

            // 计算仓位价值
            int256 positionValue = calculatePositionValue(
                int256(positionInput.openSize),
                exchange.oraclePrice,
                exchange.stepSizeScale,
                exchange.tickSizeScale,
                coinStepSizeScale
            );
            
            uint256 positionValueAbs = absInt(positionValue);
            
            // 查找风险档位
            uint256 riskTierIndex = findPositionRiskTier(exchange.riskTiers, positionValueAbs);
            RiskTier memory riskTier = exchange.riskTiers[riskTierIndex];
            
            // 计算初始保证金率
            uint32 effectiveLeverage = min(tradeSetting.leverage, riskTier.maxLeverage);
            uint32 initialMarginRatioPpm = leverageToInitialMarginRatioPpm(effectiveLeverage);
            
            // 计算IMR和MMR
            uint256 positionIMR = calculatePositionIMR(positionValueAbs, initialMarginRatioPpm);
            uint256 positionMMR = calculatePositionMMR(positionValueAbs, riskTier.maintenanceMarginRatioPpm);
            uint256 positionPV = absInt(positionValue) * PRECISION_SCALE;

            // 创建Position对象
            Position memory marginPosition = Position({
                openSize: int256(positionInput.openSize),
                openValue: int256(positionInput.openValue),
                imr: positionIMR,
                mmr: positionMMR,
                pv: positionPV
            });

            // 根据保证金模式处理
            if (tradeSetting.marginMode == 1) {
                // 全仓模式
                // 累加资金费用
                crossFundingAmount += fundingAmount;
                
                // 累加到CrossGroup
                asset.crossGroup.imr += positionIMR;
                asset.crossGroup.mmr += positionMMR;
                // 对于空仓（openSize < 0），需要减去positionPV；对于多仓，加上positionPV
                if (positionInput.openSize < 0) {
                    // 空仓：positionPV代表负债，需要从TV中减去
                    if (asset.crossGroup.tv >= positionPV) {
                        asset.crossGroup.tv -= positionPV;
                    } else {
                        // 防止下溢
                        asset.crossGroup.tv = 0;
                    }
                } else {
                    // 多仓：positionPV代表资产，需要加到TV中
                    asset.crossGroup.tv += positionPV;
                }
            } else if (tradeSetting.marginMode == 2) {
                // 逐仓模式
                // 计算资金费用的标准化值（向下取整，负数也向下取整）
                // 注意：Solidity中int256的除法是向零取整，需要特殊处理负数以匹配Go的big.Int.Div行为
                int256 fundingAmountNormalized;
                if (fundingAmount >= 0) {
                    fundingAmountNormalized = fundingAmount / int256(PRECISION_SCALE);
                } else {
                    // 负数向下取整：(a / b) 对于负数，向下取整 = (a - b + 1) / b
                    // 但更简单的方式：先取绝对值除以PRECISION_SCALE，然后取负
                    // 这确保了向下取整的行为
                    uint256 absFunding = absInt(fundingAmount);
                    uint256 quotient = absFunding / PRECISION_SCALE;
                    // 如果有余数，需要加1（向下取整）
                    if (absFunding % PRECISION_SCALE != 0) {
                        quotient += 1;
                    }
                    fundingAmountNormalized = -int256(quotient);
                }
                
                // 计算逐仓抵押品数量
                int256 collateralAmount = int256(positionInput.isolatedCollateralAmount) + fundingAmountNormalized;
                collateralAmountUint = absInt(collateralAmount);
                // 创建IsolatedGroup
                isolatedGroups[isolatedGroupCount] = IsolatedGroup({
                    collateralAmount: collateralAmountUint,
                    position: marginPosition,
                    tv: collateralAmountUint * PRECISION_SCALE + positionPV
                });
                isolatedGroupExchangeIds[isolatedGroupCount] = positionInput.exchangeId;
                isolatedGroupCount++;
            } else {
                revert("margin mode not supported");
            }
        }

        // 处理全仓资金费用
        if (crossFundingAmount != 0) {
            uint256 fundingAmountNormalized;
            if (crossFundingAmount > 0) {
                fundingAmountNormalized = uint256(crossFundingAmount) / PRECISION_SCALE;
                asset.crossGroup.collateralAmount += fundingAmountNormalized;
                asset.crossGroup.tv += fundingAmountNormalized * PRECISION_SCALE;
            } else {
                fundingAmountNormalized = uint256(-crossFundingAmount) / PRECISION_SCALE;
                if (fundingAmountNormalized <= asset.crossGroup.collateralAmount) {
                    asset.crossGroup.collateralAmount -= fundingAmountNormalized;
                    asset.crossGroup.tv -= fundingAmountNormalized * PRECISION_SCALE;
                }
            }
        }

        // 如果collateralAmount为负，需要从TV中减去negativeCollateralAdjustment
        // TV = sum(positionPV) + funding - abs(collateralAmount) * PRECISION_SCALE
        if (isCollateralNegative && asset.crossGroup.tv >= negativeCollateralAdjustment) {
            asset.crossGroup.tv -= negativeCollateralAdjustment;
        } else if (isCollateralNegative) {
            // 如果TV < negativeCollateralAdjustment，设置为0（防止下溢）
            asset.crossGroup.tv = 0;
        }

        // 调整IsolatedGroup数组大小为实际使用的大小
        IsolatedGroup[] memory finalIsolatedGroups = new IsolatedGroup[](isolatedGroupCount);
        uint64[] memory finalIsolatedGroupExchangeIds = new uint64[](isolatedGroupCount);
        for (uint256 i = 0; i < isolatedGroupCount; i++) {
            finalIsolatedGroups[i] = isolatedGroups[i];
            finalIsolatedGroupExchangeIds[i] = isolatedGroupExchangeIds[i];
        }
        
        asset.isolatedGroups = finalIsolatedGroups;
        asset.isolatedGroupExchangeIds = finalIsolatedGroupExchangeIds;
    }
}

/**
 * @title MarginAssetCalculator
 * @notice 提供跨仓转出可用金额计算的外部接口
 */
contract MarginAssetCalculator {
    /**
     * @notice 计算跨仓转出可用金额（完整版本，从原始数据计算）
     * @param crossCollateralAmount 全仓抵押品数量，精度为 collateralCoin.StepSizeScale
     * @param coinStepSizeScale 币种步长精度
     * @param orderFrozenAmount 订单冻结金额，精度为 collateralCoin.StepSizeScale + 6
     * @param positions 仓位列表（全仓和逐仓模式的仓位都会被处理）
     * @param tradeSettings 交易设置列表
     * @param exchanges 交易所信息列表（包含riskTiers数组）
     * @return availableAmount 可用金额，精度为 collateralCoin.StepSizeScale
     */
    function getCrossTransferOutAvailableAmount(
        int64 crossCollateralAmount,
        uint32 coinStepSizeScale,
        uint256 orderFrozenAmount,
        MarginAsset.PositionInput[] memory positions,
        MarginAsset.TradeSetting[] memory tradeSettings,
        MarginAsset.ExchangeInfo[] memory exchanges
    ) external pure returns (uint256 availableAmount) {
        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            crossCollateralAmount,
            coinStepSizeScale,
            positions,
            tradeSettings,
            exchanges
        );
        
        return MarginAsset.getCrossTransferOutAvailableAmount(
            asset.crossGroup.tv,
            asset.crossGroup.imr,
            orderFrozenAmount
        );
    }

    /**
     * @notice 获取完整的Asset对象（用于调试或其他需要）
     * @param crossCollateralAmount 全仓抵押品数量，精度为 collateralCoin.StepSizeScale
     * @param coinStepSizeScale 币种步长精度
     * @param positions 仓位列表
     * @param tradeSettings 交易设置列表
     * @param exchanges 交易所信息列表
     * @return asset 完整的Asset对象
     */
    function getAsset(
        int64 crossCollateralAmount,
        uint32 coinStepSizeScale,
        MarginAsset.PositionInput[] memory positions,
        MarginAsset.TradeSetting[] memory tradeSettings,
        MarginAsset.ExchangeInfo[] memory exchanges
    ) external pure returns (MarginAsset.Asset memory asset) {
        return MarginAsset.newAsset(
            crossCollateralAmount,
            coinStepSizeScale,
            positions,
            tradeSettings,
            exchanges
        );
    }
}
