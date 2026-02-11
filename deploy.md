
# 1. Update .env File
    - copy .env.example .env
    - Set the current deployment environment CURRENT_ENV (devnet/testnet/mainnet)
    - Set the private key for contract deployment PRIVATE_KEY, can be shared across multiple environments
    - Set the deployer address DEPLOYER_ADDRESS for easy on-chain balance queries
    - Set the USDC address for the current environment based on CURRENT_ENV: {CURRENT_ENV}_USDC_ADDRESS
    - Confirm the required rpc-url for the corresponding environment with operations team
    - Access control involves 3 roles:
      - settlementOperator: has permission to submit batch transactions
      - withdrawOperator: has permission to initiate withdrawal transactions
      - owner: admin permissions, can set/update other roles

# 2. Deploy MarginAssetCalculator
```
forge script ./script/MarginAsset.s.sol:MarginAssetCalculatorScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast

== Logs ==
  Deploying MarginAssetCalculator with account: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  Account balance: 62321680718882293
  MarginAssetCalculator deployed at: 0x325908E4B3C913AD418886656c2D0780757BE89f
```

Update the MarginAssetCalculator contract address in .env

# 3. Deploy StargateWithdraw
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
Update the StargateWithdraw contract address in .env

# 4. Deploy Asset Contract
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
Update the AssetProxy address in .env
Also need to update the Asset Proxy address and related addresses in devops-tools/ansible/tools/{CURRENT_ENV}_genesis.json

# 5. Configure StargateWithdraw
```
forge script ./script/StargateWithdrawSetter.s.sol:StargateWithdrawSetterScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast
== Logs ==
  Configuring StargateWithdraw with account: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  StargateWithdraw contract: 0x741a79B6073Bf74Ee80710192d28CF8386162102
  Current owner: 0xC6B7926Ad8d58b95C23cAE9E92854532ff775678
  Configuration completed!
```

# 6. Contract Verification
Verified contracts allow contract source code to be viewed in the blockchain explorer, essential for open source projects

```
forge verify-contract --watch 0x45a662952dd84ed643e1A45469e68968ee750181 src/Asset.sol:Asset --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=11155111' 
forge verify-contract --watch 0x325908E4B3C913AD418886656c2D0780757BE89f src/margin/MarginAsset.sol:MarginAssetCalculator --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=11155111' 
forge verify-contract --watch 0x741a79B6073Bf74Ee80710192d28CF8386162102 src/stargate/StargateWithdraw.sol:StargateWithdraw --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=11155111' 
forge verify-contract --watch 0xE348621f6fd4031e2b5A2E2f03c2F6140e50A9A2 src/stargate/AntStrargateAdapter.sol:AntStrargateAdapter --verifier etherscan --verifier-api-key 4KQXQ25KPRHNIVCVVRFJ1PB6SA9SGPYW89 --verifier-url 'https://api.etherscan.io/v2/api?chainid=421614' 
```

# 7. Upgrade Asset Contract (As Needed)

If there are corresponding feature upgrades to the asset contract later, you can execute this script to complete the contract upgrade while keeping the address unchanged
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

# 8. Configure Asset Contract (As Needed)
Owner management function to set different contract addresses for various features
```
forge script ./script/AssetSetter.s.sol:AssetSetterScript --rpc-url https://purple-green-wish.ethereum-sepolia.quiknode.pro/cc8a0c3a64ee15decdc7e344d53a083b08bb7160 --broadcast
```
