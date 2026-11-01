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

        // ------------------------------------------------------------------
        // L-07 (audit 2026-05-18): STORAGE-LAYOUT SAFETY — run BEFORE broadcast.
        // UUPS upgrades brick the proxy on a storage-layout collision. Validate
        // the new implementation against the deployed one with the OpenZeppelin
        // Upgrades tooling before sending the upgrade tx, e.g.:
        //
        //   npx @openzeppelin/upgrades-core validate out/build-info \
        //     --contract BasePaintMarket --reference <prev-impl-build-info>
        //
        // v1.14 (2026-07-01) changes NO storage at all — the delta is pure logic
        // (getActiveListings >= expiry boundary + self-trade guard). Storage
        // layout is byte-identical to v1.13, so the upgrade is trivially safe;
        // still run the validator as discipline before broadcasting.
        // ------------------------------------------------------------------

        // Deploy new implementation
        console.log("1. Deploying new implementation...");
        BasePaintMarket newImplementation = new BasePaintMarket();
        console.log("   New implementation deployed at:", address(newImplementation));
        console.log("");

        // Upgrade proxy to new implementation
        console.log("2. Upgrading proxy...");
        BasePaintMarket proxy = BasePaintMarket(payable(proxyAddress));

        // Snapshot state BEFORE the upgrade so we can assert it survived (v1.14
        // changes no storage, so every value below must be byte-identical after).
        uint256 miniFloorBefore = proxy.minMiniListingPrice();

        // v1.14: NO new storage and NO reinitializer. `initializeV13` was a
        // reinitializer(2) already consumed on the live proxy in the v1.13
        // upgrade — re-calling it would revert. Upgrade with EMPTY call data:
        // a plain implementation swap, nothing to initialize or front-run.
        proxy.upgradeToAndCall(address(newImplementation), "");
        console.log("   Proxy upgraded to v1.14 (no reinitializer)");
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
        console.log("   - minMiniListingPrice:", proxy.minMiniListingPrice());
        console.log("");

        // v1.14 preserves all v1.13 state — assert the mini floor is unchanged
        // across the upgrade (whatever it was, not a hardcoded value).
        require(proxy.minMiniListingPrice() == miniFloorBefore, "v1.14 upgrade lost minMiniListingPrice state");

        // Smoke-test a paginated view (getActiveListings is v1.3, not new in v1.13).
        console.log("4. Smoke-testing getActiveListings...");
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
