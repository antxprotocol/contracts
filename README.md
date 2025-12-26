# Antex Protocol Contracts

Antex Protocol 是一个跨链资产管理和提现系统，支持用户在多个链上进行资产管理、保证金计算和跨链提现操作。系统采用 UUPS 可升级代理模式，集成了 Stargate 协议实现跨链功能。

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
```

## 核心合约

- **Asset.sol**: 主合约，负责资产管理、批量更新、提现功能
- **MarginAsset.sol**: 保证金计算库，提供可用余额计算
- **StargateWithdraw.sol**: 跨链提现适配器
- **AntStrargateAdapter.sol**: Stargate 接口适配器

## 快速开始

### 安装依赖

```bash
# 安装 Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 安装项目依赖
pnpm install
forge install
```

### 构建

```bash
forge build
```

### 测试

```bash
# 运行所有测试
forge test

# 显示 gas 报告
forge test --gas-report

# 详细输出
forge test -vvv
```

## 部署流程

### 1. 部署 MarginAsset 计算器

```bash
forge script script/MarginAsset.s.sol --rpc-url <RPC_URL> --broadcast --private-key <PRIVATE_KEY>
```

### 2. 部署 Stargate 适配器

```bash
# Sepolia 链
forge script script/AntStargateAdapter.s.sol --rpc-url https://sepolia.drpc.org --broadcast

# Arbitrum Sepolia链
forge script script/AntStargateAdapter.s.sol --rpc-url https://arbitrum-sepolia.drpc.org --broadcast

```

### 3. 部署 StargateWithdraw

```bash
forge script script/StargateWithdraw.s.sol --rpc-url <RPC_URL> --broadcast --private-key <PRIVATE_KEY>
```

### 4. 部署 Asset 主合约

```bash
forge script script/Asset.s.sol --rpc-url <RPC_URL> --broadcast --private-key <PRIVATE_KEY>
```

### 5. 初始化合约

部署后需要初始化：
1. 设置 USDC 地址和默认抵押币种 ID
2. 设置结算操作员 (`setSettlementAddress`)
3. 设置提现操作员 (`setWithdrawOperator`)
4. 设置签名者列表 (`setSigners`)
5. 设置 MarginAsset 计算器地址 (`setMarginAsset`)
6. 设置 StargateWithdraw 地址 (`setStargateWithdraw`)
7. 配置跨链链信息（在 StargateWithdraw 中）

## 参考文档

- [审计文档](./AUDIT_README.md) - 详细的合约审计文档
- [Foundry Book](https://book.getfoundry.sh/) - Foundry 框架文档
- [Stargate Protocol](https://stargateprotocol.gitbook.io/stargate/) - Stargate 协议文档
