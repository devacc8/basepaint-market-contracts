// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title MockERC1271Wallet
 * @notice Minimal ERC-1271 smart-contract wallet for tests. Models the common
 *         "contract wallet controlled by one owner EOA" case (e.g. Coinbase
 *         Smart Wallet). A signature is valid iff it is a valid ECDSA signature
 *         by `owner` over the given hash. Uses tryRecover so a bad signature
 *         returns a non-magic value instead of reverting.
 */
contract MockERC1271Wallet {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant MAGIC = 0x1626ba7e;

    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return MAGIC;
        }
        return 0xffffffff;
    }

    // ERC-1155 receiver hooks: a smart wallet buying a bundle must accept the
    // safeBatchTransferFrom (real wallets implement these, directly or via a
    // fallback handler).
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }
}
