const { ethers } = require("hardhat");

async function main() {
    console.log("Testing Ed25519 Oracle...");
    
    // Get the contract factory
    const Ed25519Oracle = await ethers.getContractFactory("Ed25519Oracle");
    
    // Deploy the oracle
    const oracle = await Ed25519Oracle.deploy(
        ethers.parseEther("1"), // minimumStake: 1 ETH
        5000,                   // consensusThreshold: 50%
        300,                    // consensusTimeout: 5 minutes
        3600                    // maxDataAge: 1 hour
    );
    
    await oracle.waitForDeployment();
    console.log("Oracle deployed at:", await oracle.getAddress());
    
    // Get initial stats
    const stats = await oracle.getOracleStats();
    console.log("Initial stats:", {
        totalNodes: stats[0].toString(),
        totalStake: ethers.formatEther(stats[1]),
        minStake: ethers.formatEther(stats[2]),
        consensusThreshold: stats[3].toString(),
        consensusTimeout: stats[4].toString(),
        maxDataAge: stats[5].toString()
    });
    
    // Test data
    const testPublicKey = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const testMessageHash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const testSignature = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    // Test verification (should be false initially)
    const isVerified = await oracle.isVerified(testPublicKey, testMessageHash, testSignature);
    console.log("Initial verification result:", isVerified);
    
    console.log("Oracle test completed successfully!");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });

