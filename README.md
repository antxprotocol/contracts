# AntX Protocol Contracts

AntX Protocol is a cross-chain asset management and withdrawal system that supports users in managing assets, calculating margins, and performing cross-chain withdrawal operations across multiple chains. The system uses the UUPS upgradeable proxy pattern and integrates the Stargate protocol to implement cross-chain functionality.

## Project Structure

```
contracts/
├── src/                          # Source code directory
│   ├── Asset.sol                 # Main contract: Asset management and withdrawal core logic
│   ├── interfaces/
│   │   └── IAsset.sol           # Asset contract interface definition
│   ├── margin/
│   │   └── MarginAsset.sol      # Margin asset calculation library
│   ├── stargate/
│   │   ├── StargateWithdraw.sol # Stargate cross-chain withdrawal adapter
│   │   └── AntStrargateAdapter.sol # Stargate interface adapter
│   └── mock/
│       └── MockToken.sol        # Mock Token for testing
├── test/                         # Test files directory
├── script/                       # Deployment scripts directory
└── lib/                          # Third-party dependency libraries
```

## Core Contracts

- **Asset.sol**: Main contract responsible for asset management, batch updates, and withdrawal functionality
- **MarginAsset.sol**: Margin calculation library providing available balance calculations
- **StargateWithdraw.sol**: Cross-chain withdrawal adapter
- **AntStrargateAdapter.sol**: Stargate interface adapter

## Quick Start

### Install Dependencies

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install project dependencies
pnpm install
forge install
```

### Build

```bash
forge build
```

### Test

```bash
# Run all tests
forge test

# Show gas report
forge test --gas-report

# Verbose output
forge test -vvv
```

## Deployment Process

### 1. Deploy MarginAsset Calculator

```bash
forge script script/MarginAsset.s.sol --rpc-url <RPC_URL> --broadcast --private-key <PRIVATE_KEY>
```

### 2. Deploy Stargate Adapter

```bash
# Sepolia chain
forge script script/AntStargateAdapter.s.sol --rpc-url https://sepolia.drpc.org --broadcast

# Arbitrum Sepolia chain
forge script script/AntStargateAdapter.s.sol --rpc-url https://arbitrum-sepolia.drpc.org --broadcast

```

### 3. Deploy StargateWithdraw

```bash
forge script script/StargateWithdraw.s.sol --rpc-url <RPC_URL> --broadcast --private-key <PRIVATE_KEY>
```

### 4. Deploy Asset Main Contract

```bash
forge script script/Asset.s.sol --rpc-url <RPC_URL> --broadcast --private-key <PRIVATE_KEY>
```

### 5. Initialize Contracts

After deployment, initialization is required:
1. Set USDC address and default collateral currency ID
2. Set settlement operator (`setSettlementAddress`)
3. Set withdrawal operator (`setWithdrawOperator`)
4. Set signer list (`setSigners`)
5. Set MarginAsset calculator address (`setMarginAsset`)
6. Set StargateWithdraw address (`setStargateWithdraw`)
7. Configure cross-chain information (in StargateWithdraw)

## Reference Documentation

- [Foundry Book](https://book.getfoundry.sh/) - Foundry framework documentation
- [Stargate Protocol](https://stargateprotocol.gitbook.io/stargate/) - Stargate protocol documentation
