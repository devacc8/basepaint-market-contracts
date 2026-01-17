// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/mocks/MockBasePaint.sol";

/**
 * @title MintSecondYear1Set
 * @notice Script to mint a second complete Year 1 set (Days 1-365) to a wallet
 * @dev Creates a scenario where user has 2 complete Year 1 sets
 */
contract MintSecondYear1Set is Script {
    function run() external {
        // Get private key from environment
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        // Get contract addresses from environment
        address basePaintAddress = vm.envAddress("BASEPAINT_ADDRESS");
        address targetWallet = vm.envAddress("SELLER_YEAR2_ADDRESS");

        console.log("=== Minting Second Year 1 Set ===");
        console.log("BasePaint NFT:", basePaintAddress);
        console.log("Target Wallet:", targetWallet);
        console.log("");

        MockBasePaint basePaint = MockBasePaint(basePaintAddress);

        // Check current balance before minting
        console.log("=== Before Minting ===");
        console.log("Day 1 balance:", basePaint.balanceOf(targetWallet, 1));
        console.log("Day 365 balance:", basePaint.balanceOf(targetWallet, 365));
        console.log("Day 730 balance:", basePaint.balanceOf(targetWallet, 730));
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        console.log("Minting Days 1-365 (second set) via mintBundle...");
        basePaint.mintBundle(targetWallet, 1, 365);
        console.log("Mint complete!");
        console.log("");

        vm.stopBroadcast();

        // Verify final state
        console.log("=== After Minting ===");
        console.log("Day 1 balance:", basePaint.balanceOf(targetWallet, 1), "(should be 2)");
        console.log("Day 100 balance:", basePaint.balanceOf(targetWallet, 100), "(should be 2)");
        console.log("Day 365 balance:", basePaint.balanceOf(targetWallet, 365), "(should be 2)");
        console.log("Day 366 balance:", basePaint.balanceOf(targetWallet, 366), "(should be 1)");
        console.log("Day 730 balance:", basePaint.balanceOf(targetWallet, 730), "(should be 1)");
        console.log("");
        console.log("Result: 2 complete Year 1 sets (Days 1-365: x2 each)");
        console.log("        + 1 Year 2 extension (Days 366-730: x1 each)");
    }
}
