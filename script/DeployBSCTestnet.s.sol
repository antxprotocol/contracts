// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Asset} from "../src/Asset.sol";
import {MarginAssetCalculator} from "../src/margin/MarginAsset.sol";
import {BLS12381} from "../src/bls/BLS12381.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Minimal mock ERC20 for testnet (no real USDC needed).
contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {
        _mint(msg.sender, 1_000_000_000 * 1e18);
    }
    function decimals() public pure override returns (uint8) { return 18; }
}

/// @notice Deploy full Asset + BLS12381 verifier on BSC Testnet (chainId=97).
///
/// Prerequisites:
///   - Deployer wallet has tBNB (BSC testnet faucet: https://testnet.bnbchain.org/faucet-smart)
///   - forge installed
///
/// Usage:
///   export PRIVATE_KEY=<your_deployer_privkey_hex>
///   FOUNDRY_PROFILE=deploy forge script script/DeployBSCTestnet.s.sol:DeployBSCTestnetScript \
///     --rpc-url https://data-seed-prebsc-1-s1.binance.org:8545 \
///     --broadcast --legacy -vvv
///   (--legacy disables EIP-1559, required on BSC)
///
/// After deployment, fill printed addresses into relayer config/local.yaml:
///   ChainInfos[0].ChainID: 97
///   ChainInfos[0].Url: https://data-seed-prebsc-1-s1.binance.org:8545
///   ChainInfos[0].PoolContractAddress: <Asset proxy addr>
///   DeployAddress: <deployer addr>
///   DeployerPrivateKey: <PRIVATE_KEY>
contract DeployBSCTestnetScript is Script {
    // BLS G1 Generator in EIP-2537 format (128 bytes)
    bytes constant G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    bytes constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    // EIP-2537 G1 pubkeys (sk=0x01*32 / 0x02*32 / 0x03*32)
    bytes constant PK0 =
        hex"000000000000000000000000000000000a1a1c26055a329817a5759d877a2795f9499b97d6056edde0eea39512f24e8bc874b4471f0501127abb1ea0d9f68ac10000000000000000000000000000000011392125a1c3750363c2c97d9650fb78696e6428db8ff9efaf0471cbfd20324916ab545746db83756d335e92f9e8c8b8";
    bytes constant PK1 =
        hex"000000000000000000000000000000000004066a1a5cb9cdf244e45f0a59cf579a78d90ac0bc24663565264601c1c9251c0aa3dfb9835b520e0ba0f211a6696c000000000000000000000000000000000250fee58f12e98c72bd7de41a2c57df2c35452a4abfb0cc2691eb363f7bb9897c38f8f94ab4f8d63673b61128f11b9e";
    bytes constant PK2 =
        hex"000000000000000000000000000000000355519968b7db86b1ceb2261e179f6cde1a6010b8588e4a1a59eae804c9eed5f3e3d433a69dabb1eb7403c9c2721116000000000000000000000000000000000e3e5890e55ee5cd46fbe01d22cfde2f1570f1e6a06c5719fab0bf77ac63f787ff34cecff52085d6369db4eeaed764a3";

    function run() external {
        uint256 deployerPrivKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivKey);
        console.log("Deployer:", deployer);
        console.log("Deployer balance:", deployer.balance);

        vm.startBroadcast(deployerPrivKey);

        // 1. Deploy mock USDC
        MockUSDC usdc = new MockUSDC();
        console.log("MockUSDC deployed at:", address(usdc));

        // 2. Deploy BLS12381 verifier (uses BSC EIP-2537 precompile)
        BLS12381 blsVerifier = new BLS12381(DST, G1_GENERATOR);
        console.log("BLS12381 verifier deployed at:", address(blsVerifier));

        // 3. Deploy MarginAssetCalculator (required by Asset.availableAmount)
        MarginAssetCalculator marginAssetCalculator = new MarginAssetCalculator();
        console.log("MarginAssetCalculator deployed at:", address(marginAssetCalculator));

        // 4. Deploy full Asset implementation + proxy
        Asset impl = new Asset();
        console.log("Asset impl deployed at:", address(impl));

        bytes memory initData = abi.encodeWithSelector(
            Asset.initialize.selector,
            address(usdc),
            uint64(1) // defaultCollateralCoinId
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        Asset asset = Asset(payable(address(proxy)));
        console.log("Asset proxy deployed at:", address(proxy));

        // 5. Configure operators (deployer acts as both settlement and withdraw operator)
        asset.setSettlementAddress(deployer);
        asset.setWithdrawOperator(deployer);

        // 6. Register MarginAssetCalculator
        asset.setMarginAsset(address(marginAssetCalculator));

        // 7. Register BLS verifier
        asset.setBls(address(blsVerifier));

        // 8. Register 3 BLS validators, threshold=2
        bytes[] memory pks = new bytes[](3);
        pks[0] = PK0;
        pks[1] = PK1;
        pks[2] = PK2;
        asset.setSettlementValidators(pks, 2);
        console.log("Settlement validators registered (threshold=2/3)");

        console.log("");
        console.log("=== Copy into relayer config/local.yaml ===");
        console.log("ChainInfos[0].ChainID: 97");
        console.log("ChainInfos[0].Url: https://data-seed-prebsc-1-s1.binance.org:8545");
        console.log("ChainInfos[0].PoolContractAddress:", address(proxy));
        console.log("DeployAddress:", deployer);
        console.log("DeployerPrivateKey: <your PRIVATE_KEY>");

        vm.stopBroadcast();
    }
}
