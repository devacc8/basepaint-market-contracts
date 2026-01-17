// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/mocks/MockBasePaint.sol";

/**
 * @title MintPartialDuplicates
 * @notice Script to mint partial duplicate NFTs (Days 1-200) to a specific wallet
 * @dev Creates a scenario where user has 1 complete set + 0.5 incomplete set
 */
contract MintPartialDuplicates is Script {
    function run() external {
        // Get private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        // Get contract addresses from environment
        address basePaintAddress = vm.envAddress("BASEPAINT_NFT");
        address targetWallet = vm.envAddress("TARGET_WALLET");

        console.log("=== Minting Partial Duplicates ===");
        console.log("BasePaint NFT:", basePaintAddress);
        console.log("Target Wallet:", targetWallet);
        console.log("");

        MockBasePaint basePaint = MockBasePaint(basePaintAddress);

        // Prepare array of day numbers
        uint256[] memory dayNumbers = new uint256[](200);

        for (uint256 i = 0; i < 200; i++) {
            dayNumbers[i] = i + 1; // Day 1-200
        }

        vm.startBroadcast(deployerPrivateKey);

        console.log("Minting Days 1-200 (duplicate) via batchMint...");
        basePaint.batchMint(targetWallet, dayNumbers);
        console.log("Batch mint complete!");
        console.log("");

        vm.stopBroadcast();

        // Verify final state
        console.log("=== Verification ===");
        console.log("Day 1 balance:", basePaint.balanceOf(targetWallet, 1), "(should be 2)");
        console.log("Day 100 balance:", basePaint.balanceOf(targetWallet, 100), "(should be 2)");
        console.log("Day 200 balance:", basePaint.balanceOf(targetWallet, 200), "(should be 2)");
        console.log("Day 201 balance:", basePaint.balanceOf(targetWallet, 201), "(should be 1)");
        console.log("Day 365 balance:", basePaint.balanceOf(targetWallet, 365), "(should be 1)");
        console.log("");
        console.log("Result: 1 complete set + 0.5 partial set (200/365 duplicates)");
    }
}
