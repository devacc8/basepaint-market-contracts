// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {BasePaintMarket} from "../src/BasePaintMarket.sol";
import {MockBasePaint} from "../src/mocks/MockBasePaint.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployTestnet
 * @notice Deployment script for Base Sepolia testnet
 * @dev Deploys MockBasePaint, MockWETH, and BasePaintMarket with proxy
 */
contract DeployTestnet is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying from:", deployer);
        console.log("Deployer balance:", deployer.balance);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy MockBasePaint
        console.log("\n=== Deploying MockBasePaint ===");
        MockBasePaint basePaint = new MockBasePaint();
        console.log("MockBasePaint deployed at:", address(basePaint));

        // 2. Use canonical WETH on Base Sepolia (same address as mainnet)
        console.log("\n=== Using Canonical WETH ===");
        address weth = 0x4200000000000000000000000000000000000006;
        console.log("WETH address:", weth);
        console.log("Note: This is the canonical WETH on Base (same on mainnet and testnet)");

        // 3. Deploy BasePaintMarket implementation
        console.log("\n=== Deploying BasePaintMarket Implementation ===");
        BasePaintMarket implementation = new BasePaintMarket();
        console.log("BasePaintMarket implementation at:", address(implementation));

        // 4. Deploy ERC1967 Proxy
        console.log("\n=== Deploying ERC1967 Proxy ===");
        bytes memory initData = abi.encodeWithSelector(
            BasePaintMarket.initialize.selector,
            address(basePaint),
            weth, // canonical WETH address
            deployer // initial owner
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        console.log("Proxy deployed at:", address(proxy));

        // Wrap proxy in BasePaintMarket interface
        BasePaintMarket market = BasePaintMarket(payable(address(proxy)));

        // 5. Verify initialization
        console.log("\n=== Verification ===");
        console.log("Market basePaint:", address(market.basePaint()));
        console.log("Market weth:", address(market.weth()));
        console.log("Market platformFee:", market.platformFee());
        console.log("Market minListingPrice:", market.minListingPrice());

        vm.stopBroadcast();

        // 6. Print summary
        console.log("\n=== Deployment Summary ===");
        console.log("MockBasePaint:     ", address(basePaint));
        console.log("WETH (canonical):  ", weth);
        console.log("Market (proxy):    ", address(market));
        console.log("Implementation:    ", address(implementation));
        console.log("\nSave these addresses to frontend/lib/constants.ts");

        // 7. Print next steps
        console.log("\n=== Next Steps ===");
        console.log("1. Verify contracts on BaseScan");
        console.log("2. Update frontend/lib/constants.ts with addresses");
        console.log("3. Run SetupTestData.s.sol to create test bundles");
        console.log("4. Test on frontend");
    }
}
