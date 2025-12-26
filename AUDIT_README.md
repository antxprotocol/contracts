# Antex Protocol 智能合约审计文档

## 项目概述

Antex Protocol 是一个跨链资产管理和提现系统，支持用户在多个链上进行资产管理和跨链提现操作。系统采用 UUPS 可升级代理模式，集成了 Stargate 协议实现跨链功能。

## 项目结构

```
contracts/
├── src/                          # 源代码目录
│   ├── Asset.sol                 # 主合约：资产管理与提现核心逻辑
│   ├── interfaces/
│   │   └── IAsset.sol           # Asset 合约接口定义
│   ├── margin/
│   │   └── MarginAsset.sol      # 保证金资产计算库
│   ├── stargate/
│   │   ├── StargateWithdraw.sol # Stargate 跨链提现适配器
│   │   └── AntStrargateAdapter.sol # Stargate 接口适配器
│   └── mock/
│       └── MockToken.sol        # 测试用 Mock Token
├── test/                         # 测试文件目录
├── script/                       # 部署脚本目录
└── lib/                          # 第三方依赖库
    ├── openzeppelin-contracts/   # OpenZeppelin 合约库
    ├── openzeppelin-contracts-upgradeable/ # OpenZeppelin 可升级合约库
    └── murky/                    # Merkle 树工具库
```

## 技术栈

- **Solidity 版本**: 0.8.28
- **框架**: Foundry
- **代理模式**: UUPS (Universal Upgradeable Proxy Standard)
- **跨链协议**: Stargate (LayerZero)
- **主要依赖**:
  - OpenZeppelin Contracts (可升级版本)
  - Stargate Finance EVM V2
  - LayerZero OApp V2

## 核心合约功能

### 1. Asset.sol - 主合约

`Asset` 合约是整个系统的核心，负责资产管理、批量更新和跨链提现功能。

#### 主要功能模块

##### 1.1 资产管理
- **批量更新资产信息** (`batchUpdate`)
  - 更新币种信息 (Coin)
  - 更新交易所信息 (Exchange)
  - 更新资金费率索引 (FundingIndex)
  - 更新预言机价格 (OraclePrice)
  - 更新子账户信息 (Subaccount)
  - 更新永续资产信息 (PerpetualAsset)
  - 支持批量 ID 和序列号管理，防止重复提交

##### 1.2 提现功能
- **批量提现** (`batchWithdraw`)
  - 由提现操作员 (`withdrawOperator`) 执行
  - 支持批量处理多个用户的提现请求
  - 验证用户签名和订单 ID 唯一性
  - 支持同链和跨链提现

- **强制提现** (`forceWithdraw`)
  - 用户可在时间锁（7天）后强制提现
  - 无需操作员签名，用户自主发起
  - 适用于紧急情况下的资产提取

- **可用余额查询** (`availableAmount`)
  - 计算用户可提现余额
  - 考虑保证金、持仓、资金费率等因素
  - 支持按子账户 ID 查询

##### 1.3 跨链提现
- 集成 Stargate 协议实现跨链资产转移
- 自动计算跨链手续费（ETH）
- 支持多链提现（需预先配置链信息）
- 失败时自动退款

##### 1.4 紧急提现
- **紧急提现代币** (`emergencyWithdraw`)
  - 需要至少 2 个授权签名者签名
  - 支持多签验证机制
  - 仅限 USDC 代币

- **紧急提现 ETH** (`emergencyWithdrawETH`)
  - 多签验证机制
  - 用于提取合约中的 ETH（跨链手续费）

##### 1.5 权限管理
- **Owner**: 合约所有者，可升级合约、设置操作员和签名者
- **SettlementOperator**: 结算操作员，负责批量更新资产信息
- **WithdrawOperator**: 提现操作员，负责执行批量提现
- **Signers**: 授权签名者列表，用于紧急提现的多签验证

#### 安全特性

1. **重入保护**: 使用 `ReentrancyGuard` 防止重入攻击
2. **可升级性**: UUPS 代理模式，支持合约升级
3. **签名验证**: ECDSA 签名验证用户提现请求
4. **时间锁**: 强制提现需要等待 7 天时间锁
5. **订单 ID 唯一性**: 防止重复提现
6. **余额验证**: 提现前验证用户可用余额
7. **多签机制**: 紧急提现需要多个授权签名者签名

### 2. MarginAsset.sol - 保证金资产计算库

`MarginAsset` 是一个库合约，实现了保证金资产相关的计算逻辑。

#### 主要功能

##### 2.1 资产计算
- **创建资产对象** (`newAsset`)
  - 从原始数据构建完整的资产对象
  - 处理交叉保证金和逐仓保证金
  - 计算持仓价值、初始保证金、维持保证金

##### 2.2 可用余额计算
- **计算可转出可用金额** (`getCrossTransferOutAvailableAmount`)
  - 公式: `availableAmount = (TV - IMR - orderFrozenAmount) / PPM_SCALE`
  - TV: 总价值 (Total Value)
  - IMR: 初始保证金要求 (Initial Margin Requirement)
  - orderFrozenAmount: 订单冻结金额

##### 2.3 辅助计算函数
- 持仓价值计算 (`calculatePositionValue`)
- 初始保证金计算 (`calculatePositionIMR`)
- 维持保证金计算 (`calculatePositionMMR`)
- 资金费率计算 (`calculateFundingAmount`)
- 风险等级查找 (`findPositionRiskTier`)

#### MarginAssetCalculator 合约

提供外部接口，供 `Asset` 合约调用进行可用余额计算。

### 3. StargateWithdraw.sol - 跨链提现适配器

`StargateWithdraw` 合约负责处理跨链提现的具体实现。

#### 主要功能

##### 3.1 跨链提现
- **执行跨链提现** (`crossChainWithdraw`)
  - 调用 Stargate 协议进行跨链转账
  - 处理跨链手续费（ETH）
  - 失败时自动退款

##### 3.2 手续费计算
- **准备跨链参数** (`prepareTakeTaxi`)
  - 计算跨链手续费
  - 准备发送参数
  - 返回需要发送的 ETH 数量

##### 3.3 链管理
- 支持多链配置
- 链 ID 到 LayerZero Endpoint ID 的映射
- 链支持状态管理

#### 安全特性

1. **重入保护**: 使用 `ReentrancyGuard`
2. **错误处理**: try-catch 机制处理跨链失败
3. **自动退款**: 失败时自动退还 USDC 和 ETH
4. **权限控制**: Owner 可管理链配置

### 4. AntStrargateAdapter.sol - Stargate 接口适配器

`AntStrargateAdapter` 是 Stargate 接口的适配器，封装了 Stargate 协议调用。

#### 主要功能

- 实现 `IStargate` 接口
- 代理调用底层 Stargate 合约
- 提供便捷的跨链参数准备函数

## 关键数据结构

### BatchUpdateData
```solidity
struct BatchUpdateData {
    MarginAsset.Coin[] coinUpdates;
    MarginAsset.Exchange[] exchangeUpdates;
    MarginAsset.FundingIndex[] fundingIndexUpdates;
    MarginAsset.OraclePrice[] oraclePriceUpdates;
    MarginAsset.Subaccount[] subaccountUpdates;
    MarginAsset.PerpetualAsset[] perpetualAssetUpdates;
}
```

### MarginAsset 相关结构
- `Coin`: 币种信息
- `Exchange`: 交易所信息
- `Subaccount`: 子账户信息
- `PerpetualAsset`: 永续资产信息
- `Position`: 持仓信息
- `RiskTier`: 风险等级

## 关键事件

- `UserWithdraw`: 用户提现事件
- `CrossChainWithdraw`: 跨链提现事件
- `ForceWithdraw`: 强制提现事件
- `BatchUpdated`: 批量更新事件
- `EmergencyWithdraw`: 紧急提现事件

## 审计重点

### 1. 权限控制
- Owner 权限是否过大
- 操作员权限是否合理
- 多签机制是否安全

### 2. 资金安全
- 提现逻辑是否正确
- 余额计算是否准确
- 跨链转账是否安全

### 3. 重入攻击
- 所有外部调用是否受保护
- 状态更新顺序是否正确

### 4. 整数溢出
- 所有计算是否安全
- 精度处理是否正确

### 5. 时间锁机制
- 强制提现时间锁是否合理
- 批量更新时间戳是否正确

### 6. 签名验证
- 签名哈希是否正确
- 签名者验证是否严格

### 7. 跨链安全
- Stargate 集成是否正确
- 失败处理是否完善
- 手续费计算是否准确

### 8. 可升级性
- UUPS 升级是否安全
- 存储布局是否兼容

## 部署说明

合约使用 Foundry 框架进行部署，部署脚本位于 `script/` 目录：

- `Asset.s.sol`: Asset 主合约部署脚本
- `StargateWithdraw.s.sol`: Stargate 适配器部署脚本
- `MarginAsset.s.sol`: MarginAsset 计算器部署脚本

## 测试

测试文件位于 `test/` 目录，使用 Foundry 测试框架编写。

运行测试：
```bash
forge test
```

## 版本信息

- Solidity: 0.8.28
- Foundry: 最新版本
- OpenZeppelin: 可升级版本

## 联系方式

如有审计相关问题，请联系项目团队。

