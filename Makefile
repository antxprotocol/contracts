-include .env
export

# ─────────────────────────────────────────────────────────────────────────────
# Deploy: full deployment (Asset + BLS verifier + MockUSDC)
# Script: script/DeployBSCTestnet.s.sol:DeployBSCTestnetScript
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: deploy-testnet
deploy-testnet:
	FOUNDRY_PROFILE=deploy PRIVATE_KEY=$(BSC_TESTNET_PRIVATE_KEY) \
	forge script script/DeployBSCTestnet.s.sol:DeployBSCTestnetScript \
		--rpc-url $(BSC_TESTNET_RPC_URL) \
		--broadcast --legacy -vvv

.PHONY: deploy-mainnet
deploy-mainnet:
	@echo "WARNING: deploying to BSC MAINNET. Press Enter to continue, Ctrl+C to abort."
	@read _confirm
	# NOTE: uses the same deploy script as testnet; ensure env vars point to mainnet values
	FOUNDRY_PROFILE=deploy PRIVATE_KEY=$(BSC_MAINNET_PRIVATE_KEY) \
	forge script script/DeployBSCTestnet.s.sol:DeployBSCTestnetScript \
		--rpc-url $(BSC_MAINNET_RPC_URL) \
		--broadcast --legacy \
		--verify --etherscan-api-key $(BSCSCAN_API_KEY) \
		-vvv

.PHONY: deploy-sepolia
deploy-sepolia:
	FOUNDRY_PROFILE=deploy PRIVATE_KEY=$(BSC_TESTNET_PRIVATE_KEY) \
	forge script script/DeploySepoliaTestnet.s.sol:DeploySepoliaTestnetScript \
		--rpc-url $(SEPOLIA_RPC_URL) \
		--broadcast \
		--verify --etherscan-api-key $(ETHERSCAN_API_KEY) \
		-vvv

# ─────────────────────────────────────────────────────────────────────────────
# Upgrade: UUPS proxy upgrade (Asset implementation only)
# Script: script/AssetUpgrade.s.sol:AssetUpgradeScript
# Requires BSC_TESTNET_ASSET_PROXY_ADDRESS / BSC_MAINNET_ASSET_PROXY_ADDRESS /
#          SEPOLIA_ASSET_PROXY_ADDRESS in .env
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: upgrade-testnet
upgrade-testnet:
	PRIVATE_KEY=$(BSC_TESTNET_PRIVATE_KEY) \
	CURRENT_ENV=testnet \
	TESTNET_ASSET_PROXY_ADDRESS=$(BSC_TESTNET_ASSET_PROXY_ADDRESS) \
	forge script script/AssetUpgrade.s.sol:AssetUpgradeScript \
		--rpc-url $(BSC_TESTNET_RPC_URL) \
		--broadcast --legacy \
		--verify --etherscan-api-key $(BSCSCAN_TESTNET_API_KEY) \
		-vvv

.PHONY: upgrade-sepolia
upgrade-sepolia:
	PRIVATE_KEY=$(BSC_TESTNET_PRIVATE_KEY) \
	CURRENT_ENV=sepolia \
	SEPOLIA_ASSET_PROXY_ADDRESS=$(SEPOLIA_ASSET_PROXY_ADDRESS) \
	forge script script/AssetUpgrade.s.sol:AssetUpgradeScript \
		--rpc-url $(SEPOLIA_RPC_URL) \
		--broadcast \
		--verify --etherscan-api-key $(ETHERSCAN_API_KEY) \
		-vvv

.PHONY: upgrade-mainnet
upgrade-mainnet:
	@echo "WARNING: upgrading on BSC MAINNET. Press Enter to continue, Ctrl+C to abort."
	@read _confirm
	PRIVATE_KEY=$(BSC_MAINNET_PRIVATE_KEY) \
	CURRENT_ENV=mainnet \
	MAINNET_ASSET_PROXY_ADDRESS=$(BSC_MAINNET_ASSET_PROXY_ADDRESS) \
	forge script script/AssetUpgrade.s.sol:AssetUpgradeScript \
		--rpc-url $(BSC_MAINNET_RPC_URL) \
		--broadcast --legacy \
		--verify --etherscan-api-key $(BSCSCAN_API_KEY) \
		-vvv

# ─────────────────────────────────────────────────────────────────────────────
# Test: BLS fork tests against BSC Testnet (requires BSC RPC)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: test-bls
test-bls:
	forge test --match-contract BLSHashCheckTest -vvv \
		--fork-url $(BSC_TESTNET_RPC_URL)
	forge test --match-contract BLSE2ET -vvv \
		--fork-url $(BSC_TESTNET_RPC_URL)

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Deploy (full):"
	@echo "  deploy-testnet     Deploy Asset+BLS to BSC Testnet (chainId=97)"
	@echo "  deploy-sepolia     Deploy Asset+BLS to Sepolia Testnet (chainId=11155111)"
	@echo "  deploy-mainnet     Deploy Asset+BLS to BSC Mainnet (requires confirmation)"
	@echo ""
	@echo "Upgrade (UUPS proxy):"
	@echo "  upgrade-testnet    Upgrade Asset impl on BSC Testnet"
	@echo "  upgrade-sepolia    Upgrade Asset impl on Sepolia Testnet"
	@echo "  upgrade-mainnet    Upgrade Asset impl on BSC Mainnet (requires confirmation)"
	@echo ""
	@echo "Test:"
	@echo "  test-bls           Run BLS fork tests against BSC Testnet RPC"
	@echo ""
	@echo "Config: edit .env to set BSC_TESTNET_PRIVATE_KEY / BSC_MAINNET_PRIVATE_KEY"
	@echo "        Set SEPOLIA_RPC_URL and ETHERSCAN_API_KEY for Sepolia targets"
	@echo "        After deploy, fill *_ASSET_PROXY_ADDRESS in .env"
	@echo ""
