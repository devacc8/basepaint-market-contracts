// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {BasePaintMarket} from "../src/BasePaintMarket.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title RedeployMarket
 * @notice Redeploy Market with correct optimized MockBasePaint address
 */
contract RedeployMarket is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Use existing optimized MockBasePaint
        address basePaint = 0x5B28829ED3626Ed54f537414Acca41b3028C4620;
        address weth = 0x4200000000000000000000000000000000000006;

        console.log("Deploying from:", deployer);
        console.log("Using MockBasePaint:", basePaint);
        console.log("Using WETH:", weth);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy new Market implementation
        console.log("\n=== Deploying NEW BasePaintMarket Implementation ===");
        BasePaintMarket implementation = new BasePaintMarket();
        console.log("Implementation deployed at:", address(implementation));

        // 2. Deploy new ERC1967 Proxy
        console.log("\n=== Deploying NEW ERC1967 Proxy ===");
        bytes memory initData = abi.encodeWithSelector(
            BasePaintMarket.initialize.selector,
            basePaint, // Optimized MockBasePaint
            weth, // Canonical WETH
            deployer // Owner
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        console.log("Proxy deployed at:", address(proxy));

        BasePaintMarket market = BasePaintMarket(payable(address(proxy)));

        // 3. Set testnet-friendly parameters
        console.log("\n=== Setting Testnet Parameters ===");
        market.setMinListingPrice(0.1 ether);
        console.log("Min listing price set to:", market.minListingPrice());

        // 4. Verify initialization
        console.log("\n=== Verification ===");
        console.log("Market basePaint:", address(market.basePaint()));
        console.log("Market weth:", address(market.weth()));
        console.log("Market platformFee:", market.platformFee());
        console.log("Market minListingPrice:", market.minListingPrice());

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("MockBasePaint (existing): ", basePaint);
        console.log("WETH (canonical):         ", weth);
        console.log("Market (NEW proxy):       ", address(market));
        console.log("Implementation (NEW):     ", address(implementation));

        console.log("\n=== Next Steps ===");
        console.log("1. Update .env and documentation with new Market addresses");
        console.log("2. Sellers need to approve NEW Market address");
        console.log("3. Buyers need to approve WETH for NEW Market address");
        console.log("4. NFTs are already minted in optimized MockBasePaint!");
    }
}
