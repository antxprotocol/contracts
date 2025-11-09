// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title MarginAsset
 * @notice 实现保证金资产相关计算，包括跨仓转出可用金额计算
 * @dev 完整实现了NewAsset的逻辑，能够从原始数据构造Asset对象并计算可用金额
 */
library MarginAsset {
    // 精度常量：1000000 (6位小数)
    uint256 private constant PPM_SCALE = 1e6;

    // 币种信息
    struct Coin {
        uint64 id;
        string symbol;
        uint32 stepSizeScale;
    }

    // 子账号信息结构体
    struct Subaccount {
        uint64 id; // 子账号id，必须大于0
        bytes32 chainAddress; // 子账号链地址
        string clientAccountId; // 客户自定义id，用于幂等校验，最大长度为64
        TradeSetting[] tradeSettings; // 交易设置
    }

    // 仓位信息结构体
    struct Position {
        uint64 exchangeId; // 交易所ID
        int64 openSize;   // 开仓仓位大小，多仓为正数，空仓为负数
        int64 openValue;  // 开仓价值，多仓为正数，空仓为负数
        int64 isolatedCollateralAmount;  // 逐仓抵押品数量（仅逐仓模式有效）
        int256 cacheFundingIndex;  // 缓存的资金费率指数（可为负数），精度为 collateralCoin.StepSizeScale + 6
    }

    // 永续合约资产结构体
    struct PerpetualAsset {
        uint64 subaccountId; // 子账号ID
        uint64 collateralCoinId; // 抵押品币种ID
        int64 crossCollateralAmount; // 全仓抵押品数量
        Position[] positions; // 仓位列表
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

    // 交易所信息结构体
    struct Exchange {
        uint64 exchangeId;              // 交易所ID
        string symbol;                  // 币种符号
        uint32 stepSizeScale;            // 步长精度
        uint32 tickSizeScale;            // 价格精度
        RiskTier[] riskTiers;           // 风险档位列表
    }

    // 资金费率指数信息结构体
    struct FundingIndex {
        uint64 exchangeId;              // 交易所ID
        int256 fundingIndex;           // 资金费率指数，精度为 collateralCoin.StepSizeScale + 6
        uint64 fundingIndexTime;       // 资金费率指数时间
    }

    // Oracle价格信息结构体
    struct OraclePrice {
        uint64 exchangeId;              // 交易所ID
        uint256 oraclePrice;            // Oracle价格
        uint64 oracleTime;              // Oracle时间
    }

    // Asset结构体
    struct Asset {
        uint64 subaccountId;                    // 子账号ID
        uint64 collateralCoinId;                // 抵押品币种ID
        CrossGroup crossGroup;                  // 全仓组
        IsolatedGroup[] isolatedGroups;         // 逐仓组数组
    }

    // CrossGroup结构体（全仓组）
    struct CrossGroup {
        int256 collateralAmount;                // 抵押品数量（可为负数），精度 = collateralCoin.StepSizeScale
        AssetPosition[] positions;              // 仓位数组（全仓模式的仓位）
        uint256 imr;                            // 初始保证金需求，精度 = collateralCoin.StepSizeScale + 6
        uint256 mmr;                            // 维持保证金需求，精度 = collateralCoin.StepSizeScale + 6
        int256 tv;                              // 总价值（可为负数），精度 = collateralCoin.StepSizeScale + 6
    }

    // IsolatedGroup结构体（逐仓组）
    struct IsolatedGroup {
        int256 collateralAmount;                // 抵押品数量（可为负数），精度 = collateralCoin.StepSizeScale
        AssetPosition position;                 // 仓位（逐仓模式每个组只有一个仓位）
        int256 tv;                              // 总价值（可为负数），精度 = collateralCoin.StepSizeScale + 6
    }

    // AssetPosition结构体（资产仓位）
    struct AssetPosition {
        uint64 exchangeId;                      // 交易所ID
        int256 openSize;                        // 开仓大小，精度 = exchange.StepSizeScale
        int256 openValue;                       // 开仓价值，精度 = collateralCoin.StepSizeScale
        uint256 imr;                            // 初始保证金需求，精度 = collateralCoin.StepSizeScale + 6
        uint256 mmr;                            // 维持保证金需求，精度 = collateralCoin.StepSizeScale + 6
        int256 pv;                              // 仓位价值（带符号），精度 = collateralCoin.StepSizeScale + 6
    }

    /**
     * @notice 计算跨仓转出可用金额
     * @dev 计算公式: availableAmount = (TV - IMR - orderFrozenAmount) / PPM_SCALE
     *      如果计算结果小于0，返回0
     *      
     * @param tv 总价值 (Total Value，可为负数)，精度为 collateralCoin.StepSizeScale + 6
     * @param imr 初始保证金需求 (Initial Margin Requirement)，精度为 collateralCoin.StepSizeScale + 6
     * @param orderFrozenAmount 订单冻结金额，精度为 collateralCoin.StepSizeScale + 6
     * @return availableAmount 可用金额，精度为 collateralCoin.StepSizeScale
     */
    function getCrossTransferOutAvailableAmount(
        int256 tv,
        uint256 imr,
        uint256 orderFrozenAmount,
        CrossGroup memory crossGroup
    ) internal pure returns (int256 availableAmount) {
        // 检查是否会下溢: 如果 TV < IMR + orderFrozenAmount，返回0
        // 先检查imr + orderFrozenAmount是否溢出，如果溢出则直接返回0
        if (imr > type(uint256).max - orderFrozenAmount) {
            return 0;
        }
        
        // 将imr和orderFrozenAmount转换为int256进行比较
        int256 requiredAmount = int256(imr) + int256(orderFrozenAmount);
        
        // 检查是否会下溢: 如果 TV < IMR + orderFrozenAmount，返回0
        if (tv < requiredAmount) {
            return 0;
        }
        
        // 计算: (TV - IMR - orderFrozenAmount) / PPM_SCALE
        int256 result = (tv - requiredAmount) / int256(PPM_SCALE);
        
        int256 tmpValue = crossGroup.collateralAmount;
        for (uint256 i = 0; i < crossGroup.positions.length; i++) {
            tmpValue = tmpValue + crossGroup.positions[i].openValue;
        }
        if (result < tmpValue) {
            return 0;
        }
        if (result < 0) {
            return 0;
        }
        return result;
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
        return uint32(PPM_SCALE / uint256(leverage));
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
        int256 cacheFundingIndex,
        int256 fundingIndex,
        uint32 stepSizeScale,
        uint32 tickSizeScale,
        uint32 coinStepSizeScale
    ) internal pure returns (int256 fundingAmount) {
        // 计算资金费率差值
        int256 fundingDiff = cacheFundingIndex - fundingIndex;
        
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
     * @dev 根据Go代码中的NewAsset函数实现，完全一致的输入输出参数和算法逻辑
     * @param collateralCoin 抵押品币种信息
     * @param exchanges 交易所信息列表
     * @param oraclePrices Oracle价格列表（通过exchangeId查找）
     * @param fundingIndices 资金费率指数列表（通过exchangeId查找）
     * @param subaccount 子账号信息
     * @param perpetualAsset 永续合约资产信息
     * @return asset 完整的Asset对象，包含CrossGroup和IsolatedGroup数组
     */
    function newAsset(
        Coin memory collateralCoin,
        Exchange[] memory exchanges,
        OraclePrice[] memory oraclePrices,
        FundingIndex[] memory fundingIndices,
        Subaccount memory subaccount,
        PerpetualAsset memory perpetualAsset
    ) internal pure returns (Asset memory asset) {
        // 参数验证（与Go代码一致）
        require(collateralCoin.id > 0, "collateralCoin is invalid");
        require(exchanges.length > 0, "exchanges is empty");
        require(subaccount.id > 0, "subaccount is invalid");
        require(perpetualAsset.subaccountId == subaccount.id, "perpetualAsset not valid: subaccountId mismatch");
        require(perpetualAsset.collateralCoinId == collateralCoin.id, "perpetualAsset not valid: collateralCoinId mismatch");

        // 构建 exchangeId 到 TradeSetting 的映射（与Go代码一致）
        // Go代码：exchangeIdToTradeSettingMap := make(map[uint64]*subaccounttypes.TradeSetting)
        TradeSetting[] memory tradeSettings = subaccount.tradeSettings;
        
        // 初始化CrossGroup
        // Go代码：
        // CollateralAmount = new(big.Int).SetInt64(perpetualAsset.CrossCollateralAmount)
        // TV = new(big.Int).Mul(new(big.Int).SetInt64(perpetualAsset.CrossCollateralAmount), big.NewInt(1000000))
        int64 crossCollateralAmount = perpetualAsset.crossCollateralAmount;
        asset.crossGroup.collateralAmount = int256(crossCollateralAmount);
        asset.crossGroup.tv = int256(crossCollateralAmount) * int256(PPM_SCALE);
        asset.crossGroup.imr = 0;
        asset.crossGroup.mmr = 0;
        
        // 设置 asset 的 subaccountId 和 collateralCoinId
        asset.subaccountId = subaccount.id;
        asset.collateralCoinId = collateralCoin.id;

        // 初始化IsolatedGroup数组（预留空间）
        Position[] memory positions = perpetualAsset.positions;
        IsolatedGroup[] memory isolatedGroups = new IsolatedGroup[](positions.length);
        uint64[] memory isolatedGroupExchangeIds = new uint64[](positions.length);
        uint256 isolatedGroupCount = 0;

        // 初始化CrossGroup的positions数组（预留空间）
        AssetPosition[] memory crossPositions = new AssetPosition[](positions.length);
        uint64[] memory crossPositionsExchangeIds = new uint64[](positions.length);
        uint256 crossPositionsCount = 0;

        int256 crossFundingAmount = 0; // 精度为 collateralCoin.StepSizeScale + 6

        // 遍历所有仓位
        for (uint256 i = 0; i < positions.length; i++) {
            Position memory positionInput = positions[i];
            
            // 查找对应的exchange
            Exchange memory exchange;
            bool exchangeFound = false;
            uint256 exchangeIndex = 0;
            
            for (uint256 j = 0; j < exchanges.length; j++) {
                if (exchanges[j].exchangeId == positionInput.exchangeId) {
                    exchange = exchanges[j];
                    exchangeFound = true;
                    exchangeIndex = j;
                    break;
                }
            }
            
            require(exchangeFound, "exchange not found");
            // Go代码：if exchange.QuoteCoinId != collateralCoin.Id { return error }
            // 注意：在 Solidity 中，Exchange 结构体中没有 QuoteCoinId 字段，需要在调用时确保匹配
            // Go代码：if exchange.GetPerpetual() == nil { return error }
            // 注意：在 Solidity 中，如果 riskTiers 为空，则认为不支持永续合约
            require(exchange.riskTiers.length > 0, "exchange not support perpetual");

            // 查找对应的tradeSetting
            TradeSetting memory tradeSetting;
            bool tradeSettingFound = false;
            
            for (uint256 j = 0; j < tradeSettings.length; j++) {
                if (tradeSettings[j].exchangeId == positionInput.exchangeId) {
                    tradeSetting = tradeSettings[j];
                    tradeSettingFound = true;
                    break;
                }
            }
            
            require(tradeSettingFound && tradeSetting.leverage > 0, "trade setting not valid");

            // 查找对应的oraclePrice和fundingIndex
            uint256 oraclePrice = 0;
            bool oraclePriceFound = false;
            int256 fundingIndex = 0;
            
            for (uint256 k = 0; k < oraclePrices.length; k++) {
                if (oraclePrices[k].exchangeId == positionInput.exchangeId) {
                    oraclePrice = oraclePrices[k].oraclePrice;
                    oraclePriceFound = true;
                    break;
                }
            }
            
            for (uint256 k = 0; k < fundingIndices.length; k++) {
                if (fundingIndices[k].exchangeId == positionInput.exchangeId) {
                    fundingIndex = fundingIndices[k].fundingIndex;
                    break;
                }
            }
            // 如果没有找到，fundingIndex 保持为 0（与 Go 代码行为一致）
            
            require(oraclePriceFound && oraclePrice > 0, "oracle price not valid");

            // 解析 cacheFundingIndex（Go代码：cacheFundingIndex, ok := new(big.Int).SetString(position.CacheFundingIndex, 10)）
            // 在 Solidity 中，cacheFundingIndex 已经是 int256 类型，直接使用
            int256 cacheFundingIndex = positionInput.cacheFundingIndex;

            // 计算资金费用：fundingAmount = openSize * (cacheFundingIndex - fundingIndex)
            // Go代码：fundingAmount := new(big.Int).Mul(positionOpenSize, new(big.Int).Sub(cacheFundingIndex, fundingIndex))
            int256 fundingAmount = calculateFundingAmount(
                int256(positionInput.openSize),
                cacheFundingIndex,
                fundingIndex,
                exchange.stepSizeScale,
                exchange.tickSizeScale,
                collateralCoin.stepSizeScale
            );

            // 计算仓位价值：positionValue = (openSize * oraclePrice) / (10^(stepSizeScale + tickSizeScale - coinStepSizeScale))
            int256 positionValue = calculatePositionValue(
                int256(positionInput.openSize),
                oraclePrice,
                exchange.stepSizeScale,
                exchange.tickSizeScale,
                collateralCoin.stepSizeScale
            );
            
            uint256 positionValueAbs = absInt(positionValue);
            
            // 查找风险档位
            uint256 riskTierIndex = findPositionRiskTier(exchange.riskTiers, positionValueAbs);
            RiskTier memory riskTier = exchange.riskTiers[riskTierIndex];
            
            // 计算初始保证金率（如果杠杆超过风险档位最大杠杆，使用风险档位最大杠杆）
            // Go代码：initialMarginRatioPpm, err := LeverageToInitialMarginRatioPpm(sdkmath.Min(tradeSetting.Leverage, riskTier.MaxLeverage))
            uint32 effectiveLeverage = min(tradeSetting.leverage, riskTier.maxLeverage);
            uint32 initialMarginRatioPpm = leverageToInitialMarginRatioPpm(effectiveLeverage);
            
            // 计算IMR和MMR
            uint256 positionIMR = calculatePositionIMR(positionValueAbs, initialMarginRatioPpm);
            uint256 positionMMR = calculatePositionMMR(positionValueAbs, riskTier.maintenanceMarginRatioPpm);
            
            // 计算PV：PV = positionValue * PPM_SCALE（带符号）
            // Go代码：PV: new(big.Int).Mul(positionValue, big.NewInt(1000000))
            int256 positionPV = positionValue * int256(PPM_SCALE);

            // 创建AssetPosition对象
            AssetPosition memory marginPosition = AssetPosition({
                exchangeId: positionInput.exchangeId,
                openSize: int256(positionInput.openSize),
                openValue: int256(positionInput.openValue),
                imr: positionIMR,
                mmr: positionMMR,
                pv: positionPV
            });

            // 根据保证金模式处理
            if (tradeSetting.marginMode == 1) {
                // 全仓模式
                // Go代码：crossFundingAmount = new(big.Int).Add(crossFundingAmount, fundingAmountNormalized)
                crossFundingAmount += fundingAmount;
                
                // 累加到CrossGroup
                // Go代码：
                // crossGroup.IMR = new(big.Int).Add(crossGroup.IMR, marginPosition.IMR)
                // crossGroup.MMR = new(big.Int).Add(crossGroup.MMR, marginPosition.MMR)
                // crossGroup.TV = new(big.Int).Add(crossGroup.TV, marginPosition.PV)
                asset.crossGroup.imr += positionIMR;
                asset.crossGroup.mmr += positionMMR;
                // 累加PV到TV（PV是带符号的，直接累加即可）
                asset.crossGroup.tv += positionPV;
                
                // 添加仓位到CrossGroup的positions数组
                crossPositions[crossPositionsCount] = marginPosition;
                crossPositionsExchangeIds[crossPositionsCount] = positionInput.exchangeId;
                crossPositionsCount++;
            } else if (tradeSetting.marginMode == 2) {
                // 逐仓模式
                // Go代码：tmpAmount := new(big.Int).Div(fundingAmountNormalized, big.NewInt(1000000))
                // big.Int.Div 对于负数也是向下取整
                int256 fundingAmountNormalized;
                if (fundingAmount >= 0) {
                    fundingAmountNormalized = fundingAmount / int256(PPM_SCALE);
                } else {
                    // 负数向下取整：对于负数，big.Int.Div是向下取整
                    uint256 absFunding = absInt(fundingAmount);
                    uint256 quotient = absFunding / PPM_SCALE;
                    // 如果有余数，需要加1（向下取整）
                    if (absFunding % PPM_SCALE != 0) {
                        quotient += 1;
                    }
                    fundingAmountNormalized = -int256(quotient);
                }
                
                // 计算逐仓抵押品数量：collateralAmount = isolatedCollateralAmount + tmpAmount
                // Go代码：collateralAmount := new(big.Int).Add(new(big.Int).SetInt64(position.IsolatedCollateralAmount), tmpAmount)
                int256 collateralAmount = int256(positionInput.isolatedCollateralAmount) + fundingAmountNormalized;
                
                // 创建IsolatedGroup
                // Go代码：TV: new(big.Int).Add(new(big.Int).Mul(collateralAmount, big.NewInt(1000000)), marginPosition.PV)
                int256 isolatedTV = collateralAmount * int256(PPM_SCALE) + positionPV;
                isolatedGroups[isolatedGroupCount] = IsolatedGroup({
                    collateralAmount: collateralAmount,
                    position: marginPosition,
                    tv: isolatedTV
                });
                isolatedGroupExchangeIds[isolatedGroupCount] = positionInput.exchangeId;
                isolatedGroupCount++;
            } else {
                revert("margin mode not supported");
            }
        }

        // 处理全仓资金费用
        // Go代码：
        // tmpAmount := new(big.Int).Div(crossFundingAmount, big.NewInt(1000000))
        // crossGroup.CollateralAmount = new(big.Int).Add(crossGroup.CollateralAmount, tmpAmount)
        // crossGroup.TV = new(big.Int).Add(crossGroup.TV, new(big.Int).Mul(tmpAmount, big.NewInt(1000000)))
        if (crossFundingAmount != 0) {
            int256 tmpAmount;
            if (crossFundingAmount >= 0) {
                tmpAmount = crossFundingAmount / int256(PPM_SCALE);
            } else {
                // 负数向下取整
                uint256 absFunding = absInt(crossFundingAmount);
                uint256 quotient = absFunding / PPM_SCALE;
                if (absFunding % PPM_SCALE != 0) {
                    quotient += 1;
                }
                tmpAmount = -int256(quotient);
            }
            
            // 更新CollateralAmount和TV
            // Go代码：
            // crossGroup.CollateralAmount = new(big.Int).Add(crossGroup.CollateralAmount, tmpAmount)
            // crossGroup.TV = new(big.Int).Add(crossGroup.TV, new(big.Int).Mul(tmpAmount, big.NewInt(1000000)))
            asset.crossGroup.collateralAmount += tmpAmount;
            asset.crossGroup.tv += tmpAmount * int256(PPM_SCALE);
        }

        // 调整CrossGroup的positions数组大小为实际使用的大小
        AssetPosition[] memory finalCrossPositions = new AssetPosition[](crossPositionsCount);
        uint64[] memory finalCrossPositionsExchangeIds = new uint64[](crossPositionsCount);
        for (uint256 i = 0; i < crossPositionsCount; i++) {
            finalCrossPositions[i] = crossPositions[i];
            finalCrossPositionsExchangeIds[i] = crossPositionsExchangeIds[i];
        }
        asset.crossGroup.positions = finalCrossPositions;

        // 调整IsolatedGroup数组大小为实际使用的大小
        IsolatedGroup[] memory finalIsolatedGroups = new IsolatedGroup[](isolatedGroupCount);
        uint64[] memory finalIsolatedGroupExchangeIds = new uint64[](isolatedGroupCount);
        for (uint256 i = 0; i < isolatedGroupCount; i++) {
            finalIsolatedGroups[i] = isolatedGroups[i];
            finalIsolatedGroupExchangeIds[i] = isolatedGroupExchangeIds[i];
        }
        
        asset.isolatedGroups = finalIsolatedGroups;
    }
}

/**
 * @title MarginAssetCalculator
 * @notice 提供跨仓转出可用金额计算的外部接口
 */
contract MarginAssetCalculator {
    /**
     * @notice 计算跨仓转出可用金额（完整版本，从原始数据计算）
     * @param collateralCoin 抵押品币种信息
     * @param exchanges 交易所信息列表
     * @param oraclePrices Oracle价格列表
     * @param fundingIndices 资金费率指数列表
     * @param subaccount 子账号信息
     * @param perpetualAsset 永续合约资产信息
     * @return availableAmount 可用金额，精度为 collateralCoin.StepSizeScale
     */
    function getCrossTransferOutAvailableAmount(
        MarginAsset.Coin memory collateralCoin,
        MarginAsset.Exchange[] memory exchanges,
        MarginAsset.OraclePrice[] memory oraclePrices,
        MarginAsset.FundingIndex[] memory fundingIndices,
        MarginAsset.Subaccount memory subaccount,
        MarginAsset.PerpetualAsset memory perpetualAsset
    ) external pure returns (int256 availableAmount) {
        MarginAsset.Asset memory asset = MarginAsset.newAsset(
            collateralCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );

        uint256 orderFrozenAmount = 0;
        // orderFrozenAmount 应该从未成交订单中计算，如果当前没有订单信息，则设为0
        // TODO: 如果将来需要支持订单冻结金额计算，需要传入订单信息
        
        return MarginAsset.getCrossTransferOutAvailableAmount(
            asset.crossGroup.tv,
            asset.crossGroup.imr,
            orderFrozenAmount,
            asset.crossGroup
        );
    }

    /**
     * @notice 获取完整的Asset对象（用于调试或其他需要）
     * @param collateralCoin 抵押品币种信息
     * @param exchanges 交易所信息列表
     * @param oraclePrices Oracle价格列表
     * @param fundingIndices 资金费率指数列表
     * @param subaccount 子账号信息
     * @param perpetualAsset 永续合约资产信息
     * @return asset 完整的Asset对象
     */
    function getAsset(
        MarginAsset.Coin memory collateralCoin,
        MarginAsset.Exchange[] memory exchanges,
        MarginAsset.OraclePrice[] memory oraclePrices,
        MarginAsset.FundingIndex[] memory fundingIndices,
        MarginAsset.Subaccount memory subaccount,
        MarginAsset.PerpetualAsset memory perpetualAsset
    ) external pure returns (MarginAsset.Asset memory asset) {
        return MarginAsset.newAsset(
            collateralCoin,
            exchanges,
            oraclePrices,
            fundingIndices,
            subaccount,
            perpetualAsset
        );
    }
}
