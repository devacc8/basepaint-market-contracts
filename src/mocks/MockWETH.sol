// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockWETH
 * @notice Mock Wrapped ETH contract for testing
 * @dev Simplified version of WETH with deposit/withdraw functionality
 */
contract MockWETH is ERC20 {
    event Deposit(address indexed account, uint256 amount);
    event Withdrawal(address indexed account, uint256 amount);

    constructor() ERC20("Mock Wrapped Ether", "MWETH") {}

    /**
     * @notice Deposit ETH and receive WETH
     */
    function deposit() public payable {
        _mint(msg.sender, msg.value);
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw ETH by burning WETH
     * @param amount Amount of WETH to burn
     */
    function withdraw(uint256 amount) public {
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");
        _burn(msg.sender, amount);

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice Allow contract to receive ETH
     */
    receive() external payable {
        deposit();
    }

    /**
     * @notice Mint WETH directly (for testing convenience)
     * @param to Recipient address
     * @param amount Amount to mint
     * @dev Only for testing - real WETH doesn't have this
     */
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
