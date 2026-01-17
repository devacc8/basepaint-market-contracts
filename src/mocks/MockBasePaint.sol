// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockBasePaint
 * @notice Mock ERC1155 contract simulating BasePaint for testing
 * @dev Only for testnet use - includes helper functions for fast bundle creation
 */
contract MockBasePaint is ERC1155, Ownable {
    /// @notice Contract name
    string public name = "Mock BasePaint";

    /// @notice Contract symbol
    string public symbol = "MBPAINT";

    constructor() ERC1155("https://basepaint.xyz/api/metadata/{id}") Ownable(msg.sender) {}

    /**
     * @notice Mint a complete bundle (range of days) in one transaction
     * @param to Recipient address
     * @param startDay First day to mint (e.g., 1)
     * @param endDay Last day to mint (e.g., 365)
     * @dev Helper function for testing - allows fast creation of complete bundles
     *      Uses mintBatch for gas efficiency
     */
    function mintBundle(address to, uint256 startDay, uint256 endDay) external {
        require(startDay > 0 && startDay <= endDay, "Invalid range");
        require(endDay <= 730, "Max 730 days");

        uint256 count = endDay - startDay + 1;
        uint256[] memory ids = new uint256[](count);
        uint256[] memory amounts = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            ids[i] = startDay + i;
            amounts[i] = 1;
        }

        _mintBatch(to, ids, amounts, "");
    }

    /**
     * @notice Mint a single day NFT with specified amount
     * @param to Recipient address
     * @param day Day number (1-730)
     * @param amount Number of copies to mint
     */
    function mint(address to, uint256 day, uint256 amount) external {
        require(day > 0 && day <= 730, "Invalid day");
        require(amount > 0, "Amount must be > 0");
        _mint(to, day, amount, "");
    }

    /**
     * @notice Mint specific days in batch
     * @param to Recipient address
     * @param dayNumbers Array of day numbers to mint
     * @dev Useful for creating incomplete bundles for testing
     */
    function batchMint(address to, uint256[] calldata dayNumbers) external {
        for (uint256 i = 0; i < dayNumbers.length; i++) {
            require(dayNumbers[i] > 0 && dayNumbers[i] <= 730, "Invalid day");
            _mint(to, dayNumbers[i], 1, "");
        }
    }

    /**
     * @notice Burn a day NFT with specified amount (for testing edge cases)
     * @param from Address to burn from
     * @param day Day number to burn
     * @param amount Number of copies to burn
     */
    function burn(address from, uint256 day, uint256 amount) external {
        require(balanceOf(from, day) >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be > 0");
        _burn(from, day, amount);
    }

    /**
     * @notice Set custom URI
     * @param newuri New base URI
     */
    function setURI(string memory newuri) external onlyOwner {
        _setURI(newuri);
    }
}
