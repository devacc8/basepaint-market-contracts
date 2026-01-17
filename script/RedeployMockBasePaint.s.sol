// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MockBasePaint} from "../src/mocks/MockBasePaint.sol";

/**
 * @title RedeployMockBasePaint
 * @notice Redeploy MockBasePaint with optimized mintBundle
 */
contract RedeployMockBasePaint is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        console.log("=== Deploying Optimized MockBasePaint ===");
        MockBasePaint basePaint = new MockBasePaint();
        console.log("MockBasePaint deployed at:", address(basePaint));

        vm.stopBroadcast();

        console.log("\n=== Next Steps ===");
        console.log("1. Update BASEPAINT address in SetupTestData.s.sol to:", address(basePaint));
        console.log("2. Update basePaint in Market contract (owner call)");
    }
}
