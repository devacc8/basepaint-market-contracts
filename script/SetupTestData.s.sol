// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MockBasePaint} from "../src/mocks/MockBasePaint.sol";
import {BasePaintMarket} from "../src/BasePaintMarket.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title SetupTestData
 * @notice Create test bundles and setup test wallets
 * @dev Run after DeployTestnet.s.sol
 */
contract SetupTestData is Script {
    // Addresses from deployment (UPDATED - Redeployed Market)
    address constant BASEPAINT = 0x5B28829ED3626Ed54f537414Acca41b3028C4620; // MockBasePaint (optimized)
    address constant WETH = 0x4200000000000000000000000000000000000006; // Canonical WETH on Base
    address constant MARKET = 0xEE584A4CD392BBCe88F79FDAB868d393a4743367; // Market Proxy (NEW)

    // Test wallet addresses (from WALLETS_SETUP.md)
    address constant SELLER_YEAR1 = 0x188fE25F4db529347F3F0Bfd2DF29bB8D43CAcBC; // Wallet #1
    address constant SELLER_YEAR2 = 0x29D6496a9A90b1F13cBD37Ef56823E0A17A0bbB9; // Wallet #2
    address constant SELLER_INCOMPLETE = 0x12bAd7Ce06609FB1a9A1d43F1F85619B826FC4dD; // Wallet #3
    address constant BUYER_ALICE = 0xd076C7Adb788511D48aa48BbD3b4971DD159e4F9; // Wallet #4
    address constant BUYER_BOB = 0x909217B8E48622b58f666425d7ECbA6eBF0B69e0; // Wallet #5

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        require(BASEPAINT != address(0), "Update BASEPAINT address!");
        require(MARKET != address(0), "Update MARKET address!");

        MockBasePaint basePaint = MockBasePaint(BASEPAINT);
        BasePaintMarket market = BasePaintMarket(payable(MARKET));
        IERC20 weth = IERC20(WETH);

        vm.startBroadcast(deployerPrivateKey);

        console.log("=== Setting up test data ===\n");

        // 0. Lower minimum listing price for testnet (0.1 ETH instead of 1 ETH)
        console.log("Updating minListingPrice to 0.1 ETH for testnet...");
        market.setMinListingPrice(0.1 ether);
        console.log("  New minListingPrice:", market.minListingPrice());
        console.log("  This allows 0.2 ETH and 0.4 ETH listings\n");

        // 1. Mint Year 1 bundle to Seller_Year1
        if (SELLER_YEAR1 != address(0)) {
            console.log("Minting Year 1 bundle to Seller_Year1...");
            basePaint.mintBundle(SELLER_YEAR1, 1, 365);
            console.log("  Days 1-365 minted to:", SELLER_YEAR1);
            console.log("  Balance day 1:", basePaint.balanceOf(SELLER_YEAR1, 1));
            console.log("  Balance day 365:", basePaint.balanceOf(SELLER_YEAR1, 365));
        }

        // 2. Mint Year 2 bundle to Seller_Year2
        if (SELLER_YEAR2 != address(0)) {
            console.log("\nMinting Year 2 bundle to Seller_Year2...");
            basePaint.mintBundle(SELLER_YEAR2, 1, 730);
            console.log("  Days 1-730 minted to:", SELLER_YEAR2);
            console.log("  Balance day 1:", basePaint.balanceOf(SELLER_YEAR2, 1));
            console.log("  Balance day 730:", basePaint.balanceOf(SELLER_YEAR2, 730));
        }

        // 3. Mint incomplete bundle to Seller_Incomplete (missing 101 days)
        if (SELLER_INCOMPLETE != address(0)) {
            console.log("\nMinting incomplete bundle to Seller_Incomplete...");
            basePaint.mintBundle(SELLER_INCOMPLETE, 1, 264);
            console.log("  Days 1-264 minted to:", SELLER_INCOMPLETE);
            console.log("  Missing days: 265-365 (101 tokens)");
            console.log("  Balance day 1:", basePaint.balanceOf(SELLER_INCOMPLETE, 1));
            console.log("  Balance day 264:", basePaint.balanceOf(SELLER_INCOMPLETE, 264));
            console.log("  Balance day 265:", basePaint.balanceOf(SELLER_INCOMPLETE, 265));
        }

        // 4. Note about WETH for buyers
        console.log("\n=== WETH Setup ===");
        console.log("WETH address:", WETH);
        console.log("\nBuyers need to wrap ETH -> WETH manually:");
        console.log("1. Send ETH to WETH contract (it has deposit() function)");
        console.log("2. Or use cast: cast send", WETH, '"deposit()"', "--value 10ether --private-key $BUYER_PK");

        if (BUYER_ALICE != address(0)) {
            console.log("\nBuyer_Alice current WETH balance:", weth.balanceOf(BUYER_ALICE));
        }

        if (BUYER_BOB != address(0)) {
            console.log("Buyer_Bob current WETH balance:", weth.balanceOf(BUYER_BOB));
        }

        vm.stopBroadcast();

        console.log("\n=== Setup Complete ===");
        console.log("\nNext steps:");
        console.log("1. Each seller should run setApprovalForAll(MARKET, true)");
        console.log("2. Each buyer should run WETH.approve(MARKET, type(uint256).max)");
        console.log("3. Sellers can create listings via frontend");
        console.log("4. Buyers can purchase or make offers");
        console.log("\nManual approval commands:");
        console.log(
            "For sellers: cast send <BASEPAINT> 'setApprovalForAll(address,bool)' <MARKET> true --private-key $SELLER_PK"
        );
        console.log(
            "For buyers: cast send <WETH> 'approve(address,uint256)' <MARKET> $(cast max-uint) --private-key $BUYER_PK"
        );
    }
}
