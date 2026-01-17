// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {BasePaintMarket} from "../src/BasePaintMarket.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployMainnet
 * @notice Deployment script for Base Mainnet
 * @dev Deploys BasePaintMarket with UUPS proxy using real BasePaint and WETH
 */
contract DeployMainnet is Script {
    // Base Mainnet addresses
    address constant BASEPAINT = 0xBa5e05cb26b78eDa3A2f8e3b3814726305dcAc83;
    address constant WETH = 0x4200000000000000000000000000000000000006;

    function run() external {
        // Get deployer from Frame (unlocked account)
        address deployer = msg.sender;

        console.log("=== Base Mainnet Deployment ===");
        console.log("Deploying from:", deployer);
        console.log("Deployer balance:", deployer.balance);
        console.log("");
        console.log("BasePaint:", BASEPAINT);
        console.log("WETH:", WETH);

        vm.startBroadcast();

        // 1. Deploy BasePaintMarket implementation
        console.log("\n=== Deploying BasePaintMarket Implementation ===");
        BasePaintMarket implementation = new BasePaintMarket();
        console.log("Implementation deployed at:", address(implementation));

        // 2. Deploy ERC1967 Proxy with initialize call
        console.log("\n=== Deploying ERC1967 Proxy ===");
        bytes memory initData = abi.encodeWithSelector(
            BasePaintMarket.initialize.selector,
            BASEPAINT,
            WETH,
            deployer // owner
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        console.log("Proxy deployed at:", address(proxy));

        // Wrap proxy in BasePaintMarket interface
        BasePaintMarket market = BasePaintMarket(payable(address(proxy)));

        // 3. Verify initialization
        console.log("\n=== Verification ===");
        console.log("Market basePaint:", address(market.basePaint()));
        console.log("Market weth:", address(market.weth()));
        console.log("Market owner:", market.owner());
        console.log("Market platformFee:", market.platformFee(), "(200 = 2%)");
        console.log("Market minListingPrice:", market.minListingPrice(), "wei (1 ETH)");

        vm.stopBroadcast();

        // 4. Print summary
        console.log("\n========================================");
        console.log("=== DEPLOYMENT SUCCESSFUL ===");
        console.log("========================================");
        console.log("Network:           Base Mainnet (8453)");
        console.log("Proxy Address:     ", address(proxy));
        console.log("Implementation:    ", address(implementation));
        console.log("Owner:             ", deployer);
        console.log("========================================");
        console.log("");
        console.log("SAVE THESE ADDRESSES!");
        console.log("");
        console.log("=== Next Steps ===");
        console.log("1. Verify on Basescan:");
        console.log("   forge verify-contract", address(implementation), "src/BasePaintMarket.sol:BasePaintMarket --chain-id 8453");
        console.log("2. Update backend/src/config/contracts.ts");
        console.log("3. Update Railway environment variables");
        console.log("4. Redeploy backend");
    }
}
