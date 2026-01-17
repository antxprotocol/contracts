
# 一、更新.env文件
    - copy .env.example .env
    - 设置当前要部署的环境 CURRENT_ENV (devnet/testnet/mainnet)
    - 设置部署合约的私钥PRIVATE_KEY,多个环境可以共用
    - 设置设置部署合约的地址DEPLOYER_ADDRESS,方便查询链上余额
    - 根据CURRENT_ENV设置当前环境的USDC地址 {CURRENT_ENV}_USDC_ADDRESS
    - 找运维确认对应环境所需的rpc-url
    - 权限控制涉及到3个角色
      - settlementOperator,拥有提交批次交易的权限
      - withdrawOperator,拥有发起提现交易的权限
      - owner,管理员权限，可以设置/更新其他角色
# 二、部署MarginAssetCalculator
```
forge script ./script/MarginAsset.s.sol:MarginAssetCalculatorScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast

== Logs ==
  Deploying MarginAssetCalculator with account: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  Account balance: 62321680718882293
  MarginAssetCalculator deployed at: 0x325908E4B3C913AD418886656c2D0780757BE89f
```

更新MarginAssetCalculator合约地址到.env中

# 三、 部署StragateWithdraw
```
forge script ./script/StargateWithdraw.s.sol:StargateWithdrawScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast

== Logs ==
  Deploying StargateWithdraw with account: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  Account balance: 60356884670358591
  USDC address: 0x2F6F07CDcf3588944Bf4C42aC74ff24bF56e7590
  Stargate Pool address: 0x4985b8fcEA3659FD801a5b857dA1D00e985863F0
  StargateWithdraw deployed at: 0x741a79B6073Bf74Ee80710192d28CF8386162102
  USDC token: 0x2F6F07CDcf3588944Bf4C42aC74ff24bF56e7590
  Stargate Pool: 0x4985b8fcEA3659FD801a5b857dA1D00e985863F0
  Owner: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
```
更新StragateWithdraw合约地址到.env中

# 四、 部署Asset合约
```
forge script ./script/Asset.s.sol:AssetScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast
== Logs ==
  USDC address at: 0x2F6F07CDcf3588944Bf4C42aC74ff24bF56e7590
  Settlement address at: 0x99998e313c602C1D602e6874446b3eaAB4CD7bE2
  Withdraw operator address at: 0x99998e313c602C1D602e6874446b3eaAB4CD7bE2
  Margin asset calculator address at: 0x325908E4B3C913AD418886656c2D0780757BE89f
  Stargate withdraw address at: 0x741a79B6073Bf74Ee80710192d28CF8386162102
  Asset implementation deployed at: 0x45a662952dd84ed643e1A45469e68968ee750181
  Asset proxy deployed at: 0x8e4a6562E3578Cb086382F3b3b54D79B07e16077
  Asset (via proxy) at: 0x8e4a6562E3578Cb086382F3b3b54D79B07e16077
```
更新AssetProxy地址到env中
另外需要把Asset Proxy地址及相关地址更新到devops-tools/ansible/tools/{CURRENT_ENV}_genesis.json中

# 五、设置stargateWithdraw
```
forge script ./script/StargateWithdrawSetter.s.sol:StargateWithdrawSetterScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast
== Logs ==
  Configuring StargateWithdraw with account: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  StargateWithdraw contract: 0x741a79B6073Bf74Ee80710192d28CF8386162102
  Current owner: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  Configuration completed!
```

# 六、 合约验证
经过验证的合约，可以在浏览器上看到合约源码，开源必备

```
forge verify-contract --watch 0x45a662952dd84ed643e1A45469e68968ee750181 src/Asset.sol:Asset --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=11155111' 
forge verify-contract --watch 0x325908E4B3C913AD418886656c2D0780757BE89f src/margin/MarginAsset.sol:MarginAssetCalculator --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=11155111' 
forge verify-contract --watch 0x741a79B6073Bf74Ee80710192d28CF8386162102 src/stargate/StargateWithdraw.sol:StargateWithdraw --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=11155111' 
forge verify-contract --watch 0xE348621f6fd4031e2b5A2E2f03c2F6140e50A9A2 src/stargate/AntStrargateAdapter.sol:AntStrargateAdapter --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=421614' 
```

# 七、按需升级asset合约

后续如果asset合约有对应的功能升级，可以执行此脚本，保证地址不变的情况下，完成合约升级
```
forge script ./script/AssetUpgrade.s.sol:AssetUpgradeScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast

== Logs ==
  Private key address: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  Asset proxy address: 0x871bD685AcE3E8f5383BDbC4bfD98a31559AA8F4
  Current implementation address: 0x035b4B8A6217a2bcD62bFBE841Fe5a6C57019Bc1
  New Asset implementation deployed at: 0x23D8eeb85b86f4Df893ef25AE041d1C095d9b10E
  Asset owner: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  Upgrade completed successfully!
  New implementation address: 0x23D8eeb85b86f4Df893ef25AE041d1C095d9b10E
```

# 八、 按需设置asset合约
owner管理功能，可以设置不同的功能合约地址
```
forge script ./script/AssetSetter.s.sol:AssetSetterScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast
```