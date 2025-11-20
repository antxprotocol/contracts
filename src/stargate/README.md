# Stargate Cross-Chain Withdraw

这个目录包含了使用 Stargate 协议实现非 Arbitrum 链跨链提现的功能。

## 概述

`StargateCrossChainWithdraw` 合约是一个适配器合约，用于处理非 Arbitrum 链的跨链提现。它集成了 Stargate v2 协议，通过 LayerZero 实现跨链资产转移。

## 主要功能

1. **跨链提现**: 支持从当前链跨链提现到目标链和目标地址
2. **非 Arbitrum 链支持**: 专门为非 Arbitrum 链设计（Arbitrum 链使用其他提现方式）
3. **滑点保护**: 支持设置最小接收金额以防止滑点损失
4. **费用管理**: 支持 LayerZero 消息费用配置和退款地址设置

## 合约说明

### StargateCrossChainWithdraw

适配器合约，负责与 Stargate Pool 交互，执行跨链转账。

**主要函数**:
- `crossChainWithdraw()`: 执行跨链提现
- `quoteCrossChainFee()`: 查询跨链费用
- `setStargatePool()`: 设置 Stargate Pool 地址
- `setChainEndpoint()`: 设置链的 LayerZero 端点 ID
- `setChainSupport()`: 启用/禁用特定链的支持

### Asset 合约集成

Asset 合约已集成跨链提现功能：

**新增函数**:
- `batchCrossChainWithdraw()`: 批量跨链提现
- `setStargateAdapter()`: 设置 Stargate 适配器地址

**内部函数**:
- `_userCrossChainWithdraw()`: 处理单个用户的跨链提现逻辑

## 使用流程

1. **部署合约**:
   ```solidity
   // 部署 StargateCrossChainWithdraw
   StargateCrossChainWithdraw adapter = new StargateCrossChainWithdraw(
       usdcAddress,
       stargatePoolAddress,
       ownerAddress
   );
   
   // 在 Asset 合约中设置适配器
   asset.setStargateAdapter(address(adapter));
   ```

2. **配置链支持**:
   ```solidity
   // 设置目标链的 LayerZero 端点 ID
   adapter.setChainEndpoint(dstChainId, endpointId);
   
   // 启用链支持
   adapter.setChainSupport(dstChainId, true);
   ```

3. **执行跨链提现**:
   ```solidity
   // 查询费用
   MessagingFee memory fee = adapter.quoteCrossChainFee(
       dstChainId,
       amount,
       false // payInLzToken
   );
   
   // 执行跨链提现
   asset.batchCrossChainWithdraw(
       clientOrderIds,
       subaccountIds,
       amounts,
       signatures,
       signatureType,
       dstChainIds,
       dstAddresses,
       minAmountsLD,
       fees,
       refundAddress
   );
   ```

## 参数说明

### SendParam
- `dstEid`: 目标链的 LayerZero 端点 ID
- `to`: 目标地址（bytes32 格式）
- `amountLD`: 发送金额（本地精度）
- `minAmountLD`: 最小接收金额（滑点保护）
- `extraOptions`: 额外选项
- `composeMsg`: 组合消息
- `oftCmd`: OFT 命令

### MessagingFee
- `nativeFee`: 原生代币费用
- `lzTokenFee`: LZ 代币费用

## 安全注意事项

1. **链 ID 验证**: 合约会拒绝 Arbitrum 链（主网和测试网）的跨链请求
2. **签名验证**: 所有跨链提现都需要用户签名验证
3. **余额检查**: 提现前会检查用户可用余额
4. **滑点保护**: 通过 `minAmountLD` 参数防止滑点损失

## 支持的链

合约支持所有非 Arbitrum 链，但需要：
1. 链已配置 LayerZero 端点 ID
2. 链已启用支持
3. Stargate Pool 支持该链

## 事件

- `CrossChainWithdrawInitiated`: 跨链提现已发起
- `StargatePoolUpdated`: Stargate Pool 地址已更新
- `ChainEndpointUpdated`: 链端点 ID 已更新
- `ChainSupportUpdated`: 链支持状态已更新

## 错误处理

- `InvalidChainId`: 无效的链 ID
- `ArbitrumChainNotSupported`: 不支持 Arbitrum 链
- `ChainNotSupported`: 链未启用支持
- `InvalidStargatePool`: 无效的 Stargate Pool 地址
- `InvalidEndpointId`: 无效的端点 ID

## 参考文档

- [Stargate Protocol Documentation](https://stargateprotocol.gitbook.io/stargate/)
- [LayerZero Documentation](https://docs.layerzero.network/)
- [Stargate Contract Addresses](https://stargateprotocol.gitbook.io/stargate/developers/contract-addresses/testnet)

