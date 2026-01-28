#!/bin/bash

  # Asset implementation deployed at: 0x0BDAd3dCd2e523d90a16e81903D28cF78843bb35
  # Asset proxy deployed at: 0x43113bcF0bf7383e8001f920853569B56bD38fad

# Configuration - Update these values based on your deployment
PROXY_ADDRESS="${ASSET_PROXY_ADDRESS:-0x43113bcF0bf7383e8001f920853569B56bD38fad}"
IMPLEMENTATION_ADDRESS="${ASSET_IMPLEMENTATION_ADDRESS:-0x0BDAd3dCd2e523d90a16e81903D28cF78843bb35}"
USDC_ADDRESS="${USDC_ADDRESS:-0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d}"
DEFAULT_COLLATERAL_COIN_ID="${DEFAULT_COLLATERAL_COIN_ID:-1000}"
CHAIN_ID="${CHAIN_ID:-56}"  # BNB Mainnet
VERIFIER_API_KEY="${VERIFIER_API_KEY:-4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89}"
COMPILER_VERSION="0.8.28"
OPTIMIZER_RUNS=200

echo "=== Asset Proxy Verification Script ==="
echo ""
echo "Configuration:"
echo "  Proxy Address: $PROXY_ADDRESS"
echo "  Implementation Address: $IMPLEMENTATION_ADDRESS"
echo "  USDC Address: $USDC_ADDRESS"
echo "  Chain ID: $CHAIN_ID"
echo ""

# Encode initialize function call: initialize(address _USDC,uint64 _defaultCollateralCoinId)
echo "Encoding initialize function call..."
INIT_DATA=$(cast calldata "initialize(address,uint64)" "$USDC_ADDRESS" "$DEFAULT_COLLATERAL_COIN_ID")
echo "Initialize data: $INIT_DATA"
echo ""

# Encode constructor arguments: constructor(address implementation, bytes memory _data)
echo "Encoding constructor arguments..."
CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address,bytes)" "$IMPLEMENTATION_ADDRESS" "$INIT_DATA")
echo "Constructor args: $CONSTRUCTOR_ARGS"
echo ""

# Determine verifier URL based on chain ID
case $CHAIN_ID in
  11155111)
    VERIFIER_URL="https://api.etherscan.io/v2/api?chainid=11155111"
    EXPLORER_URL="https://sepolia.etherscan.io/address/$PROXY_ADDRESS#code"
    CHAIN_NAME="sepolia"
    ;;
  1)
    VERIFIER_URL="https://api.etherscan.io/v2/api?chainid=1"
    EXPLORER_URL="https://etherscan.io/address/$PROXY_ADDRESS#code"
    CHAIN_NAME="mainnet"
    ;;
  8453)
    VERIFIER_URL="https://api.etherscan.io/v2/api?chainid=8453"
    EXPLORER_URL="https://basescan.org/address/$PROXY_ADDRESS#code"
    CHAIN_NAME="base"
    ;;
  56)
    VERIFIER_URL="https://api.etherscan.io/v2/api?chainid=56"
    EXPLORER_URL="https://bscscan.com/address/$PROXY_ADDRESS#code"
    CHAIN_NAME="bsc"
    ;;
  *)
    VERIFIER_URL="https://api.etherscan.io/v2/api?chainid=$CHAIN_ID"
    EXPLORER_URL="https://explorer.chain/$PROXY_ADDRESS#code"
    CHAIN_NAME="unknown"
    ;;
esac

echo "Verifying Asset proxy contract..."
echo "  Chain: $CHAIN_NAME"
echo "  Verifier URL: $VERIFIER_URL"
echo ""

# Verify the proxy contract
forge verify-contract \
  --watch \
  --chain $CHAIN_NAME \
  --compiler-version $COMPILER_VERSION \
  --num-of-optimizations $OPTIMIZER_RUNS \
  "$PROXY_ADDRESS" \
  lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
  --constructor-args "$CONSTRUCTOR_ARGS" \
  --verifier etherscan \
  --verifier-api-key "$VERIFIER_API_KEY" \
  --verifier-url "$VERIFIER_URL" || {
    echo ""
    echo "❌ 自动验证失败，请使用以下信息手动验证："
    echo ""
    echo "验证页面: $EXPLORER_URL"
    echo ""
    echo "验证信息："
    echo "  - 编译器版本: v${COMPILER_VERSION}+commit.xxx"
    echo "  - 优化: Enabled ($OPTIMIZER_RUNS runs)"
    echo "  - 合约名称: ERC1967Proxy"
    echo "  - 构造函数参数: $CONSTRUCTOR_ARGS"
    echo ""
    echo "构造函数参数详情："
    echo "  - implementation: $IMPLEMENTATION_ADDRESS"
    echo "  - _data (initialize calldata): $INIT_DATA"
    echo ""
    echo "注意：需要上传完整的ERC1967Proxy源代码及其依赖项："
    echo "  - lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol"
    echo "  - lib/openzeppelin-contracts/contracts/proxy/Proxy.sol"
    echo "  - lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol"
    echo ""
    exit 1
  }

echo ""
echo "✅ === 验证完成 ==="
echo ""
echo "快速验证信息："
echo "  - 代理合约地址: $PROXY_ADDRESS"
echo "  - 实现合约地址: $IMPLEMENTATION_ADDRESS"
echo "  - USDC 地址: $USDC_ADDRESS"
echo "  - 编译器版本: $COMPILER_VERSION"
echo "  - 优化: Enabled ($OPTIMIZER_RUNS runs)"
echo "  - 构造函数参数: $CONSTRUCTOR_ARGS"
echo "  - 验证页面: $EXPLORER_URL"
echo ""
echo "提示：代理合约使用标准OpenZeppelin代码，如果自动验证失败，"
echo "     可以只验证实现合约（Asset.sol），代理合约通常不需要单独验证。"

