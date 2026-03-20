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
# BLS validators: set pubkeys + min signatures (setSettlementValidators)
# Script: script/SetBLS.s.sol:SetBLSValidatorsScript
# Requires TESTNET_BLS_PUBKEYS / MAINNET_BLS_PUBKEYS (comma-separated 0x hex)
#          TESTNET_BLS_MIN_SIGNATURES / MAINNET_BLS_MIN_SIGNATURES in .env
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: set-bls-validators-testnet
set-bls-validators-testnet:
	PRIVATE_KEY=$(BSC_TESTNET_PRIVATE_KEY) \
	CURRENT_ENV=testnet \
	forge script script/SetBLS.s.sol:SetBLSValidatorsScript \
		--rpc-url $(BSC_TESTNET_RPC_URL) \
		--broadcast --legacy -vvv

.PHONY: set-bls-validators-mainnet
set-bls-validators-mainnet:
	@echo "WARNING: updating BLS validators on BSC MAINNET. Press Enter to continue, Ctrl+C to abort."
	@read _confirm
	PRIVATE_KEY=$(BSC_MAINNET_PRIVATE_KEY) \
	CURRENT_ENV=mainnet \
	forge script script/SetBLS.s.sol:SetBLSValidatorsScript \
		--rpc-url $(BSC_MAINNET_RPC_URL) \
		--broadcast --legacy -vvv

# ─────────────────────────────────────────────────────────────────────────────
# BLS min signatures: update threshold only (setSettlementMinSignatures)
# Script: script/SetBLS.s.sol:SetBLSMinSignaturesScript
# Requires TESTNET_BLS_MIN_SIGNATURES / MAINNET_BLS_MIN_SIGNATURES in .env
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: set-bls-min-sigs-testnet
set-bls-min-sigs-testnet:
	PRIVATE_KEY=$(BSC_TESTNET_PRIVATE_KEY) \
	CURRENT_ENV=testnet \
	forge script script/SetBLS.s.sol:SetBLSMinSignaturesScript \
		--rpc-url $(BSC_TESTNET_RPC_URL) \
		--broadcast --legacy -vvv

.PHONY: set-bls-min-sigs-mainnet
set-bls-min-sigs-mainnet:
	@echo "WARNING: updating BLS min signatures on BSC MAINNET. Press Enter to continue, Ctrl+C to abort."
	@read _confirm
	PRIVATE_KEY=$(BSC_MAINNET_PRIVATE_KEY) \
	CURRENT_ENV=mainnet \
	forge script script/SetBLS.s.sol:SetBLSMinSignaturesScript \
		--rpc-url $(BSC_MAINNET_RPC_URL) \
		--broadcast --legacy -vvv

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
	@echo "  upgrade-testnet            Upgrade Asset impl on BSC Testnet"
	@echo "  upgrade-sepolia            Upgrade Asset impl on Sepolia Testnet"
	@echo "  upgrade-mainnet            Upgrade Asset impl on BSC Mainnet (requires confirmation)"
	@echo ""
	@echo "BLS validators (pubkeys + min signatures):"
	@echo "  set-bls-validators-testnet  Set BLS validator pubkeys+threshold on BSC Testnet"
	@echo "  set-bls-validators-mainnet  Set BLS validator pubkeys+threshold on BSC Mainnet (requires confirmation)"
	@echo ""
	@echo "BLS min signatures (threshold only):"
	@echo "  set-bls-min-sigs-testnet    Update BLS min-signature threshold on BSC Testnet"
	@echo "  set-bls-min-sigs-mainnet    Update BLS min-signature threshold on BSC Mainnet (requires confirmation)"
	@echo ""
	@echo "Test:"
	@echo "  test-bls                    Run BLS fork tests against BSC Testnet RPC"
	@echo ""
	@echo "Config: edit .env to set BSC_TESTNET_PRIVATE_KEY / BSC_MAINNET_PRIVATE_KEY"
	@echo "        Set SEPOLIA_RPC_URL and ETHERSCAN_API_KEY for Sepolia targets"
	@echo "        After deploy, fill *_ASSET_PROXY_ADDRESS in .env"
	@echo "        BLS: set TESTNET_BLS_PUBKEYS (comma-separated 0x hex, 128 bytes each)"
	@echo "             set TESTNET_BLS_MIN_SIGNATURES / MAINNET_BLS_MIN_SIGNATURES"
	@echo ""
