// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title MarginAsset
 * @notice Implements margin asset related calculations, including cross-margin transfer out available amount calculation
 * @dev Fully implements the NewAsset logic, able to construct Asset objects from raw data and calculate available amounts
 */
library MarginAsset {
    // Precision constant: 1000000 (6 decimal places)
    uint256 private constant PPM_SCALE = 1e6;

    // Coin information
    struct Coin {
        uint64 id;
        string symbol;
        uint32 stepSizeScale;
    }

    // Subaccount information struct
    struct Subaccount {
        uint64 id; // Subaccount ID, must be greater than 0
        bytes32 chainAddress; // Subaccount chain address
        bool isMultiSigWallet; // Whether the subaccount is a multi-signature wallet
        address multiSigWallet; // Multi-signature wallet address
        string clientAccountId; // Client-defined ID for idempotency check, maximum length 64
        TradeSetting[] tradeSettings; // Trading settings
    }

    // Position information struct
    struct Position {
        uint64 exchangeId; // Exchange ID
        int64 openSize; // Open position size, long positions are positive, short positions are negative
        int64 openValue; // Open value, long positions are positive, short positions are negative
        int64 isolatedCollateralAmount; // Isolated margin collateral amount (only valid for isolated margin mode)
        int256 cacheFundingIndex; // Cached funding rate index (can be negative), precision = collateralCoin.StepSizeScale + 6
    }

    // Perpetual asset struct
    struct PerpetualAsset {
        uint64 subaccountId; // Subaccount ID
        uint64 collateralCoinId; // Collateral coin ID
        int64 crossCollateralAmount; // Cross-margin collateral amount
        Position[] positions; // Position list
    }

    // Risk tier struct
    struct RiskTier {
        uint32 maxLeverage; // Maximum leverage
        uint32 maintenanceMarginRatioPpm; // Maintenance margin ratio, unit: parts per million
        uint64 positionValueUpperBound; // Maximum position value
    }

    // Trading settings struct
    struct TradeSetting {
        uint64 exchangeId; // Exchange ID
        uint32 leverage; // Leverage multiplier
        uint8 marginMode; // Margin mode: 1=cross-margin, 2=isolated-margin
    }

    // Exchange information struct
    struct Exchange {
        uint64 exchangeId; // Exchange ID
        string symbol; // Coin symbol
        uint32 stepSizeScale; // Step size precision
        uint32 tickSizeScale; // Price precision
        RiskTier[] riskTiers; // Risk tier list
    }

    // Funding rate index information struct
    struct FundingIndex {
        uint64 exchangeId; // Exchange ID
        int256 fundingIndex; // Funding rate index, precision = collateralCoin.StepSizeScale + 6
        uint64 fundingIndexTime; // Funding rate index time
    }

    // Oracle price information struct
    struct OraclePrice {
        uint64 exchangeId; // Exchange ID
        uint256 oraclePrice; // Oracle price
        uint64 oracleTime; // Oracle time
    }

    // Asset struct
    struct Asset {
        uint64 subaccountId; // Subaccount ID
        uint64 collateralCoinId; // Collateral coin ID
        CrossGroup crossGroup; // Cross-margin group
        IsolatedGroup[] isolatedGroups; // Isolated-margin group array
    }

    // CrossGroup struct (cross-margin group)
    struct CrossGroup {
        int256 collateralAmount; // Collateral amount (can be negative), precision = collateralCoin.StepSizeScale
        AssetPosition[] positions; // Position array (positions in cross-margin mode)
        uint256 imr; // Initial margin requirement, precision = collateralCoin.StepSizeScale + 6
        uint256 mmr; // Maintenance margin requirement, precision = collateralCoin.StepSizeScale + 6
        int256 tv; // Total value (can be negative), precision = collateralCoin.StepSizeScale + 6
    }

    // IsolatedGroup struct (isolated-margin group)
    struct IsolatedGroup {
        int256 collateralAmount; // Collateral amount (can be negative), precision = collateralCoin.StepSizeScale
        AssetPosition position; // Position (each group in isolated-margin mode has only one position)
        int256 tv; // Total value (can be negative), precision = collateralCoin.StepSizeScale + 6
    }

    // AssetPosition struct (asset position)
    struct AssetPosition {
        uint64 exchangeId; // Exchange ID
        int256 openSize; // Open size, precision = exchange.StepSizeScale
        int256 openValue; // Open value, precision = collateralCoin.StepSizeScale
        uint256 imr; // Initial margin requirement, precision = collateralCoin.StepSizeScale + 6
        uint256 mmr; // Maintenance margin requirement, precision = collateralCoin.StepSizeScale + 6
        int256 pv; // Position value (signed), precision = collateralCoin.StepSizeScale + 6
    }

    /**
     * @notice Calculate cross-margin transfer out available amount
     * @dev Calculation formula: availableAmount = (TV - IMR - orderFrozenAmount) / PPM_SCALE
     *      If the result is less than 0, return 0
     *
     * @param tv Total value (can be negative), precision = collateralCoin.StepSizeScale + 6
     * @param imr Initial margin requirement, precision = collateralCoin.StepSizeScale + 6
     * @param orderFrozenAmount Order frozen amount, precision = collateralCoin.StepSizeScale + 6
     * @return availableAmount Available amount, precision = collateralCoin.StepSizeScale
     */
    function getCrossTransferOutAvailableAmount(
        int256 tv,
        uint256 imr,
        uint256 orderFrozenAmount,
        CrossGroup memory crossGroup
    ) internal pure returns (int256 availableAmount) {
        // Check for underflow: if TV < IMR + orderFrozenAmount, return 0
        // First check if imr + orderFrozenAmount overflows, if so return 0 directly
        if (imr > type(uint256).max - orderFrozenAmount) {
            return 0;
        }

        // Convert imr and orderFrozenAmount to int256 for comparison
        int256 requiredAmount = int256(imr) + int256(orderFrozenAmount);

        // Check for underflow: if TV < IMR + orderFrozenAmount, return 0
        if (tv < requiredAmount) {
            return 0;
        }

        // Calculate: (TV - IMR - orderFrozenAmount) / PPM_SCALE
        int256 result = (tv - requiredAmount) / int256(PPM_SCALE);

        int256 tmpValue = crossGroup.collateralAmount;
        for (uint256 i = 0; i < crossGroup.positions.length; i++) {
            tmpValue = tmpValue + crossGroup.positions[i].openValue;
        }
        if (result > tmpValue) {
            result = tmpValue;
        }
        if (result < 0) {
            result = 0;
        }
        return result;
    }

    /**
     * @notice Calculate initial margin ratio from leverage (unit: parts per million)
     * @param leverage Leverage multiplier
     * @return initialMarginRatioPpm Initial margin ratio (unit: parts per million)
     */
    function leverageToInitialMarginRatioPpm(uint32 leverage) internal pure returns (uint32 initialMarginRatioPpm) {
        require(leverage > 0, "leverage must be greater than 0");
        return uint32(PPM_SCALE / uint256(leverage));
    }

    /**
     * @notice Calculate position value
     * @dev Calculation formula: positionValue = (openSize * oraclePrice) / (10^(stepSizeScale + tickSizeScale - coinStepSizeScale))
     * @param openSize Open size (signed)
     * @param oraclePrice Oracle price
     * @param stepSizeScale Step size precision
     * @param tickSizeScale Price precision
     * @param coinStepSizeScale Coin step size precision
     * @return positionValue Position value (signed), precision = coinStepSizeScale
     */
    function calculatePositionValue(
        int256 openSize,
        uint256 oraclePrice,
        uint32 stepSizeScale,
        uint32 tickSizeScale,
        uint32 coinStepSizeScale
    ) internal pure returns (int256 positionValue) {
        // Calculate (openSize * oraclePrice) / 10^(stepSizeScale + tickSizeScale - coinStepSizeScale)
        uint256 absOpenSize = absInt(openSize);
        uint256 value = absOpenSize * oraclePrice;

        uint32 scaleDiff = stepSizeScale + tickSizeScale;
        if (scaleDiff > coinStepSizeScale) {
            uint32 divisor = scaleDiff - coinStepSizeScale;
            require(divisor <= 77, "Divisor too large"); // 10^77 is the maximum value for uint256
            value = value / (10 ** divisor);
        } else if (scaleDiff < coinStepSizeScale) {
            uint32 multiplier = coinStepSizeScale - scaleDiff;
            value = value * (10 ** multiplier);
        }

        require(value <= uint256(type(int256).max), "int256 conversion overflow");
        return openSize < 0 ? -int256(value) : int256(value);
    }

    /**
     * @notice Calculate absolute value of position
     */
    function absInt(int256 x) private pure returns (uint256) {
        return x < 0 ? uint256(-x) : uint256(x);
    }

    /**
     * @notice Calculate position initial margin amount
     * @param positionValueAbs Position absolute value, precision = collateralCoin.StepSizeScale
     * @param initialMarginRatioPpm Initial margin ratio (unit: parts per million)
     * @return imr Initial margin amount, precision = collateralCoin.StepSizeScale + 6
     */
    function calculatePositionIMR(uint256 positionValueAbs, uint32 initialMarginRatioPpm)
        internal
        pure
        returns (uint256 imr)
    {
        return (positionValueAbs * uint256(initialMarginRatioPpm));
    }

    /**
     * @notice Calculate position maintenance margin amount
     * @param positionValueAbs Position absolute value, precision = collateralCoin.StepSizeScale
     * @param maintenanceMarginRatioPpm Maintenance margin ratio (unit: parts per million)
     * @return mmr Maintenance margin amount, precision = collateralCoin.StepSizeScale + 6
     */
    function calculatePositionMMR(uint256 positionValueAbs, uint32 maintenanceMarginRatioPpm)
        internal
        pure
        returns (uint256 mmr)
    {
        return (positionValueAbs * uint256(maintenanceMarginRatioPpm));
    }

    /**
     * @notice Find corresponding risk tier based on position value
     * @param riskTiers Risk tier list (must be sorted by positionValueUpperBound from small to large)
     * @param positionValueAbs Position absolute value
     * @return riskTierIndex Found risk tier index, if not found return the last tier
     */
    function findPositionRiskTier(RiskTier[] memory riskTiers, uint256 positionValueAbs)
        internal
        pure
        returns (uint256 riskTierIndex)
    {
        require(riskTiers.length > 0, "risk tiers is empty");

        // must be sorted by positionValueUpperBound from small to large
        for (uint256 i = 1; i < riskTiers.length; i++) {
            require(
                riskTiers[i].positionValueUpperBound >= riskTiers[i - 1].positionValueUpperBound,
                "risk tiers not sorted"
            );
        }
        // Iterate to find matching risk tier
        for (uint256 i = 0; i < riskTiers.length; i++) {
            uint256 upperBound = uint256(riskTiers[i].positionValueUpperBound);
            if (positionValueAbs <= upperBound) {
                return i;
            }
        }

        // Not found, return the last tier (fallback)
        return riskTiers.length - 1;
    }

    /**
     * @notice Helper function to calculate minimum value
     */
    function min(uint32 a, uint32 b) private pure returns (uint32) {
        return a < b ? a : b;
    }

    /**
     * @notice Calculate funding fee
     * @dev fundingAmount = openSize * (cacheFundingIndex - fundingIndex)
     *      Then need to convert precision from (stepSizeScale + tickSizeScale + 6) to (coinStepSizeScale + 6)
     */
    function calculateFundingAmount(
        int256 openSize,
        int256 cacheFundingIndex,
        int256 fundingIndex,
        uint32 stepSizeScale,
        uint32 tickSizeScale,
        uint32 coinStepSizeScale
    ) internal pure returns (int256 fundingAmount) {
        // Calculate funding rate difference
        int256 fundingDiff = cacheFundingIndex - fundingIndex;

        // fundingAmount = openSize * fundingDiff
        // Convert precision from (stepSizeScale + tickSizeScale + 6) to (coinStepSizeScale + 6)
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
        
        // Check for overflow: if value > int256.max, return 0
        require(value <= uint256(type(int256).max), "int256 conversion overflow");

        bool isNegative = (openSize < 0) != (fundingDiff < 0);
        return isNegative ? -int256(value) : int256(value);
    }

    /**
     * @notice Create new Asset object (calculated from raw data)
     * @dev Implemented according to the NewAsset function in Go code, with identical input/output parameters and algorithm logic
     * @param collateralCoin Collateral coin information
     * @param exchanges Exchange information list
     * @param oraclePrices Oracle price list (lookup by exchangeId)
     * @param fundingIndices Funding rate index list (lookup by exchangeId)
     * @param subaccount Subaccount information
     * @param perpetualAsset Perpetual asset information
     * @return asset Complete Asset object, including CrossGroup and IsolatedGroup arrays
     */
    function newAsset(
        Coin memory collateralCoin,
        Exchange[] memory exchanges,
        OraclePrice[] memory oraclePrices,
        FundingIndex[] memory fundingIndices,
        Subaccount memory subaccount,
        PerpetualAsset memory perpetualAsset
    ) internal pure returns (Asset memory asset) {
        // Parameter validation (consistent with Go code)
        require(collateralCoin.id > 0, "collateralCoin is invalid");
        require(exchanges.length > 0, "exchanges is empty");
        require(subaccount.id > 0, "subaccount is invalid");
        require(perpetualAsset.subaccountId == subaccount.id, "perpetualAsset not valid: subaccountId mismatch");
        require(
            perpetualAsset.collateralCoinId == collateralCoin.id, "perpetualAsset not valid: collateralCoinId mismatch"
        );

        // Build exchangeId to TradeSetting mapping (consistent with Go code)
        // Go code: exchangeIdToTradeSettingMap := make(map[uint64]*subaccounttypes.TradeSetting)
        TradeSetting[] memory tradeSettings = subaccount.tradeSettings;

        // Initialize CrossGroup
        // Go code:
        // CollateralAmount = new(big.Int).SetInt64(perpetualAsset.CrossCollateralAmount)
        // TV = new(big.Int).Mul(new(big.Int).SetInt64(perpetualAsset.CrossCollateralAmount), big.NewInt(1000000))
        int64 crossCollateralAmount = perpetualAsset.crossCollateralAmount;
        asset.crossGroup.collateralAmount = int256(crossCollateralAmount);
        asset.crossGroup.tv = int256(crossCollateralAmount) * int256(PPM_SCALE);
        asset.crossGroup.imr = 0;
        asset.crossGroup.mmr = 0;

        // Set asset's subaccountId and collateralCoinId
        asset.subaccountId = subaccount.id;
        asset.collateralCoinId = collateralCoin.id;

        // Initialize IsolatedGroup array (pre-allocate space)
        Position[] memory positions = perpetualAsset.positions;
        IsolatedGroup[] memory isolatedGroups = new IsolatedGroup[](positions.length);
        uint64[] memory isolatedGroupExchangeIds = new uint64[](positions.length);
        uint256 isolatedGroupCount = 0;

        // Initialize CrossGroup's positions array (pre-allocate space)
        AssetPosition[] memory crossPositions = new AssetPosition[](positions.length);
        uint64[] memory crossPositionsExchangeIds = new uint64[](positions.length);
        uint256 crossPositionsCount = 0;

        int256 crossFundingAmount = 0; // Precision = collateralCoin.StepSizeScale + 6

        // Iterate through all positions
        for (uint256 i = 0; i < positions.length; i++) {
            Position memory positionInput = positions[i];

            // Find corresponding exchange
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
            // Go code: if exchange.QuoteCoinId != collateralCoin.Id { return error }
            // Note: In Solidity, the Exchange struct does not have a QuoteCoinId field, need to ensure matching when calling
            // Go code: if exchange.GetPerpetual() == nil { return error }
            // Note: In Solidity, if riskTiers is empty, it is considered that perpetual contracts are not supported
            require(exchange.riskTiers.length > 0, "exchange not support perpetual");

            // Find corresponding tradeSetting
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

            // Find corresponding oraclePrice and fundingIndex
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
            // If not found, fundingIndex remains 0 (consistent with Go code behavior)

            require(oraclePriceFound && oraclePrice > 0, "oracle price not valid");

            // Parse cacheFundingIndex (Go code: cacheFundingIndex, ok := new(big.Int).SetString(position.CacheFundingIndex, 10))
            // In Solidity, cacheFundingIndex is already int256 type, use directly
            int256 cacheFundingIndex = positionInput.cacheFundingIndex;

            // Calculate funding fee: fundingAmount = openSize * (cacheFundingIndex - fundingIndex)
            // Go code: fundingAmount := new(big.Int).Mul(positionOpenSize, new(big.Int).Sub(cacheFundingIndex, fundingIndex))
            int256 fundingAmount = calculateFundingAmount(
                int256(positionInput.openSize),
                cacheFundingIndex,
                fundingIndex,
                exchange.stepSizeScale,
                exchange.tickSizeScale,
                collateralCoin.stepSizeScale
            );

            // Calculate position value: positionValue = (openSize * oraclePrice) / (10^(stepSizeScale + tickSizeScale - coinStepSizeScale))
            int256 positionValue = calculatePositionValue(
                int256(positionInput.openSize),
                oraclePrice,
                exchange.stepSizeScale,
                exchange.tickSizeScale,
                collateralCoin.stepSizeScale
            );

            uint256 positionValueAbs = absInt(positionValue);

            // Find risk tier
            uint256 riskTierIndex = findPositionRiskTier(exchange.riskTiers, positionValueAbs);
            RiskTier memory riskTier = exchange.riskTiers[riskTierIndex];

            // Calculate initial margin ratio (if leverage exceeds risk tier max leverage, use risk tier max leverage)
            // Go code: initialMarginRatioPpm, err := LeverageToInitialMarginRatioPpm(sdkmath.Min(tradeSetting.Leverage, riskTier.MaxLeverage))
            uint32 effectiveLeverage = min(tradeSetting.leverage, riskTier.maxLeverage);
            uint32 initialMarginRatioPpm = leverageToInitialMarginRatioPpm(effectiveLeverage);

            // Calculate IMR and MMR
            uint256 positionIMR = calculatePositionIMR(positionValueAbs, initialMarginRatioPpm);
            uint256 positionMMR = calculatePositionMMR(positionValueAbs, riskTier.maintenanceMarginRatioPpm);

            // Calculate PV: PV = positionValue * PPM_SCALE (signed)
            // Go code: PV: new(big.Int).Mul(positionValue, big.NewInt(1000000))
            int256 positionPV = positionValue * int256(PPM_SCALE);

            // Create AssetPosition object
            AssetPosition memory marginPosition = AssetPosition({
                exchangeId: positionInput.exchangeId,
                openSize: int256(positionInput.openSize),
                openValue: int256(positionInput.openValue),
                imr: positionIMR,
                mmr: positionMMR,
                pv: positionPV
            });

            // Process according to margin mode
            if (tradeSetting.marginMode == 1) {
                // Cross-margin mode
                // Go code: crossFundingAmount = new(big.Int).Add(crossFundingAmount, fundingAmountNormalized)
                crossFundingAmount += fundingAmount;

                // Accumulate to CrossGroup
                // Go code:
                // crossGroup.IMR = new(big.Int).Add(crossGroup.IMR, marginPosition.IMR)
                // crossGroup.MMR = new(big.Int).Add(crossGroup.MMR, marginPosition.MMR)
                // crossGroup.TV = new(big.Int).Add(crossGroup.TV, marginPosition.PV)
                asset.crossGroup.imr += positionIMR;
                asset.crossGroup.mmr += positionMMR;
                // Accumulate PV to TV (PV is signed, can accumulate directly)
                asset.crossGroup.tv += positionPV;

                // Add position to CrossGroup's positions array
                crossPositions[crossPositionsCount] = marginPosition;
                crossPositionsExchangeIds[crossPositionsCount] = positionInput.exchangeId;
                crossPositionsCount++;
            } else if (tradeSetting.marginMode == 2) {
                // Isolated-margin mode
                // Go code: tmpAmount := new(big.Int).Div(fundingAmountNormalized, big.NewInt(1000000))
                // big.Int.Div rounds down for negative numbers
                int256 fundingAmountNormalized;
                if (fundingAmount >= 0) {
                    fundingAmountNormalized = fundingAmount / int256(PPM_SCALE);
                } else {
                    // Negative number rounds down: for negative numbers, big.Int.Div rounds down
                    uint256 absFunding = absInt(fundingAmount);
                    uint256 quotient = absFunding / PPM_SCALE;
                    // If there is a remainder, need to add 1 (round down)
                    if (absFunding % PPM_SCALE != 0) {
                        quotient += 1;
                    }
                    fundingAmountNormalized = -int256(quotient);
                }

                // Calculate isolated-margin collateral amount: collateralAmount = isolatedCollateralAmount + tmpAmount
                // Go code: collateralAmount := new(big.Int).Add(new(big.Int).SetInt64(position.IsolatedCollateralAmount), tmpAmount)
                int256 collateralAmount = int256(positionInput.isolatedCollateralAmount) + fundingAmountNormalized;

                // Create IsolatedGroup
                // Go code: TV: new(big.Int).Add(new(big.Int).Mul(collateralAmount, big.NewInt(1000000)), marginPosition.PV)
                int256 isolatedTV = collateralAmount * int256(PPM_SCALE) + positionPV;
                isolatedGroups[isolatedGroupCount] =
                    IsolatedGroup({collateralAmount: collateralAmount, position: marginPosition, tv: isolatedTV});
                isolatedGroupExchangeIds[isolatedGroupCount] = positionInput.exchangeId;
                isolatedGroupCount++;
            } else {
                revert("margin mode not supported");
            }
        }

        // Process cross-margin funding fee
        // Go code:
        // tmpAmount := new(big.Int).Div(crossFundingAmount, big.NewInt(1000000))
        // crossGroup.CollateralAmount = new(big.Int).Add(crossGroup.CollateralAmount, tmpAmount)
        // crossGroup.TV = new(big.Int).Add(crossGroup.TV, new(big.Int).Mul(tmpAmount, big.NewInt(1000000)))
        if (crossFundingAmount != 0) {
            int256 tmpAmount;
            if (crossFundingAmount >= 0) {
                tmpAmount = crossFundingAmount / int256(PPM_SCALE);
            } else {
                // Negative number rounds down
                uint256 absFunding = absInt(crossFundingAmount);
                uint256 quotient = absFunding / PPM_SCALE;
                if (absFunding % PPM_SCALE != 0) {
                    quotient += 1;
                }
                tmpAmount = -int256(quotient);
            }

            // Update CollateralAmount and TV
            // Go code:
            // crossGroup.CollateralAmount = new(big.Int).Add(crossGroup.CollateralAmount, tmpAmount)
            // crossGroup.TV = new(big.Int).Add(crossGroup.TV, new(big.Int).Mul(tmpAmount, big.NewInt(1000000)))
            asset.crossGroup.collateralAmount += tmpAmount;
            asset.crossGroup.tv += tmpAmount * int256(PPM_SCALE);
        }

        // Adjust CrossGroup's positions array size to actual used size
        AssetPosition[] memory finalCrossPositions = new AssetPosition[](crossPositionsCount);
        uint64[] memory finalCrossPositionsExchangeIds = new uint64[](crossPositionsCount);
        for (uint256 i = 0; i < crossPositionsCount; i++) {
            finalCrossPositions[i] = crossPositions[i];
            finalCrossPositionsExchangeIds[i] = crossPositionsExchangeIds[i];
        }
        asset.crossGroup.positions = finalCrossPositions;

        // Adjust IsolatedGroup array size to actual used size
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
 * @notice Provides external interface for cross-margin transfer out available amount calculation
 */
contract MarginAssetCalculator {
    /**
     * @notice Calculate cross-margin transfer out available amount (full version, calculated from raw data)
     * @param collateralCoin Collateral coin information
     * @param exchanges Exchange information list
     * @param oraclePrices Oracle price list
     * @param fundingIndices Funding rate index list
     * @param subaccount Subaccount information
     * @param perpetualAsset Perpetual asset information
     * @return availableAmount Available amount, precision = collateralCoin.StepSizeScale
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
            collateralCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset
        );

        uint256 orderFrozenAmount = 0;
        // orderFrozenAmount should be calculated from unfilled orders, if there is no order information currently, set to 0
        // TODO: If order frozen amount calculation is needed in the future, order information needs to be passed in

        return MarginAsset.getCrossTransferOutAvailableAmount(
            asset.crossGroup.tv, asset.crossGroup.imr, orderFrozenAmount, asset.crossGroup
        );
    }

    /**
     * @notice Get complete Asset object (for debugging or other needs)
     * @param collateralCoin Collateral coin information
     * @param exchanges Exchange information list
     * @param oraclePrices Oracle price list
     * @param fundingIndices Funding rate index list
     * @param subaccount Subaccount information
     * @param perpetualAsset Perpetual asset information
     * @return asset Complete Asset object
     */
    function getAsset(
        MarginAsset.Coin memory collateralCoin,
        MarginAsset.Exchange[] memory exchanges,
        MarginAsset.OraclePrice[] memory oraclePrices,
        MarginAsset.FundingIndex[] memory fundingIndices,
        MarginAsset.Subaccount memory subaccount,
        MarginAsset.PerpetualAsset memory perpetualAsset
    ) external pure returns (MarginAsset.Asset memory asset) {
        return MarginAsset.newAsset(collateralCoin, exchanges, oraclePrices, fundingIndices, subaccount, perpetualAsset);
    }
}
