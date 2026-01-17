// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/BasePaintMarket.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title UpgradeMarket
 * @notice Script to upgrade BasePaintMarket implementation (UUPS pattern)
 * @dev Upgrades the implementation contract while preserving proxy state
 */
contract UpgradeMarket is Script {
    function run() external {
        // Load environment variables
        address proxyAddress = vm.envAddress("MARKET_PROXY_ADDRESS");

        // For mainnet: use OWNER_ADDRESS (Ledger) via Frame
        // For testnet: use DEPLOYER_PRIVATE_KEY
        address ownerAddress = vm.envOr("OWNER_ADDRESS", address(0));

        console.log("==========================================");
        console.log("UPGRADING BASEPAINT MARKET");
        console.log("==========================================");
        console.log("Proxy Address:", proxyAddress);

        if (ownerAddress != address(0)) {
            // Mainnet: use Frame/Ledger
            console.log("Owner (Ledger):", ownerAddress);
            console.log("");
            vm.startBroadcast(ownerAddress);
        } else {
            // Testnet: use private key
            uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
            console.log("Deployer:", vm.addr(deployerPrivateKey));
            console.log("");
            vm.startBroadcast(deployerPrivateKey);
        }

        // Deploy new implementation
        console.log("1. Deploying new implementation...");
        BasePaintMarket newImplementation = new BasePaintMarket();
        console.log("   New implementation deployed at:", address(newImplementation));
        console.log("");

        // Upgrade proxy to new implementation
        console.log("2. Upgrading proxy...");
        BasePaintMarket proxy = BasePaintMarket(payable(proxyAddress));

        // Call upgradeToAndCall with empty data (no reinitializer needed)
        proxy.upgradeToAndCall(address(newImplementation), "");
        console.log("   Proxy upgraded successfully");
        console.log("");

        // Verify upgrade
        console.log("3. Verifying upgrade...");

        // Test that old state is preserved
        uint256 nextListingId = proxy.nextListingId();
        uint256 platformFee = proxy.platformFee();
        uint256 minListingPrice = proxy.minListingPrice();

        console.log("   State verification:");
        console.log("   - nextListingId:", nextListingId);
        console.log("   - platformFee:", platformFee);
        console.log("   - minListingPrice:", minListingPrice);
        console.log("");

        // Test new function exists
        console.log("4. Testing new function getActiveListings...");
        try proxy.getActiveListings(0, 10) returns (
            uint256[] memory listingIds, BasePaintMarket.Listing[] memory listingData, uint256 totalActive
        ) {
            console.log("   Function works! Total active listings:", totalActive);
            console.log("   Returned", listingIds.length, "listings");
        } catch {
            console.log("   ERROR: Function call failed");
        }
        console.log("");

        vm.stopBroadcast();

        console.log("==========================================");
        console.log("UPGRADE COMPLETE");
        console.log("==========================================");
        console.log("Proxy:", proxyAddress);
        console.log("New Implementation:", address(newImplementation));
        console.log("");
        console.log("IMPORTANT: Update MARKET_IMPLEMENTATION_ADDRESS in .env:");
        console.log("MARKET_IMPLEMENTATION_ADDRESS=", address(newImplementation));
        console.log("==========================================");
    }
}
