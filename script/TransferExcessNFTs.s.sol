// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

/**
 * @title TransferExcessNFTs
 * @notice Transfer NFTs from SELLER_INCOMPLETE, keeping only days 1-8
 * @dev Run with: forge script script/TransferExcessNFTs.s.sol --rpc-url base_sepolia --broadcast
 */
contract TransferExcessNFTs is Script {
    // MockBasePaint on Base Sepolia
    address constant BASEPAINT = 0x5B28829ED3626Ed54f537414Acca41b3028C4620;

    // Source wallet (SELLER_INCOMPLETE)
    address constant FROM = 0x12bAd7Ce06609FB1a9A1d43F1F85619B826FC4dD;

    // Destination wallet (SELLER_YEAR1)
    address constant TO = 0x188fE25F4db529347F3F0Bfd2DF29bB8D43CAcBC;

    function run() external {
        uint256 privateKey = vm.envUint("SELLER_INCOMPLETE_PK");

        vm.startBroadcast(privateKey);

        IERC1155 basePaint = IERC1155(BASEPAINT);

        // Transfer days 9-365 (357 days)
        // Do it in batches to avoid gas limit

        // Batch 1: days 9-108 (100 days)
        console.log("Transferring days 9-108...");
        _transferBatch(basePaint, 9, 108);

        // Batch 2: days 109-208 (100 days)
        console.log("Transferring days 109-208...");
        _transferBatch(basePaint, 109, 208);

        // Batch 3: days 209-308 (100 days)
        console.log("Transferring days 209-308...");
        _transferBatch(basePaint, 209, 308);

        // Batch 4: days 309-365 (57 days)
        console.log("Transferring days 309-365...");
        _transferBatch(basePaint, 309, 365);

        vm.stopBroadcast();

        console.log("Done! Kept days 1-8, transferred days 9-365");
    }

    function _transferBatch(IERC1155 basePaint, uint256 startDay, uint256 endDay) internal {
        uint256 count = endDay - startDay + 1;
        uint256[] memory ids = new uint256[](count);
        uint256[] memory amounts = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            ids[i] = startDay + i;
            // Transfer all copies (we have 2 for most days, 1 for day 365)
            amounts[i] = basePaint.balanceOf(FROM, ids[i]);
        }

        basePaint.safeBatchTransferFrom(FROM, TO, ids, amounts, "");
    }
}
