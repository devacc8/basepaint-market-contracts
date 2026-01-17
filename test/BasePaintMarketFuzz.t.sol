// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/BasePaintMarket.sol";
import "../src/mocks/MockBasePaint.sol";
import "../src/mocks/MockWETH.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * Extended Fuzz Testing for BasePaintMarket Security Audit
 * Focus: Finding edge cases, overflow/underflow, signature vulnerabilities
 */
contract BasePaintMarketFuzzTest is Test {
    BasePaintMarket public market;
    MockBasePaint public basePaint;
    MockWETH public weth;

    address public owner = address(1);
    address public seller = address(2);
    uint256 public buyerPrivateKey = 0xB0B;
    address public buyer;
    address public attacker = address(4);

    uint256 constant MIN_LISTING_PRICE = 1 ether;
    uint256 constant DEFAULT_DURATION = 30 days;

    function setUp() public {
        buyer = vm.addr(buyerPrivateKey);

        basePaint = new MockBasePaint();
        weth = new MockWETH();

        BasePaintMarket implementation = new BasePaintMarket();
        bytes memory initData =
            abi.encodeWithSelector(BasePaintMarket.initialize.selector, address(basePaint), address(weth), owner);

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        market = BasePaintMarket(payable(address(proxy)));

        // Give seller bundles - only 1 of each for most tests
        for (uint256 i = 1; i <= 730; i++) {
            basePaint.mint(seller, i, 1);
        }

        vm.prank(seller);
        basePaint.setApprovalForAll(address(market), true);
    }

    // ===========================================
    // FUZZ TEST: Price Manipulation
    // ===========================================

    function testFuzz_ListingPriceOverflow(uint256 price) public {
        // Test with extreme values - ensure price is valid
        vm.assume(price >= MIN_LISTING_PRICE);
        // Avoid overflow in fee calculation: price * 10000 must not overflow
        // Max safe price: type(uint256).max / 10000
        vm.assume(price <= type(uint256).max / 10000);

        vm.prank(seller);
        market.createListing(BasePaintMarket.BundleType.YEAR_1, price, DEFAULT_DURATION);

        // Check fee calculation doesn't overflow
        uint256 fee = (price * market.platformFee()) / 10000;
        assertLe(fee, price, "Fee should never exceed price");

        // Verify listing was created correctly
        BasePaintMarket.Listing memory listing = market.getListing(1);
        assertEq(listing.price, price);
        assertTrue(listing.active);
    }

    // ===========================================
    // FUZZ TEST: Signature Replay Attack
    // ===========================================

    function testFuzz_SignatureReplayProtection(uint256 salt1, uint256 salt2, uint256 price, uint256 expiresAt)
        public
    {
        vm.assume(price > 0 && price < 100 ether);
        vm.assume(expiresAt > block.timestamp);
        vm.assume(salt1 != salt2); // Different salts

        // Setup buyer with WETH
        vm.deal(buyer, 200 ether);
        vm.startPrank(buyer);
        weth.deposit{value: 200 ether}();
        weth.approve(address(market), type(uint256).max);
        vm.stopPrank();

        // Create two offers with same params but different salts
        uint256 nonce = market.offerNonces(buyer);
        BasePaintMarket.CollectionOfferParams memory offer1 = BasePaintMarket.CollectionOfferParams({
            buyer: buyer,
            bundleType: BasePaintMarket.BundleType.YEAR_1,
            price: price,
            expiresAt: expiresAt,
            salt: salt1,
            nonce: nonce
        });

        bytes32 structHash1 = keccak256(
            abi.encode(
                market.COLLECTION_OFFER_TYPEHASH(),
                offer1.buyer,
                offer1.bundleType,
                offer1.price,
                offer1.expiresAt,
                offer1.salt,
                offer1.nonce
            )
        );

        bytes32 digest1 = _hashTypedDataV4(structHash1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(buyerPrivateKey, digest1);
        bytes memory signature1 = abi.encodePacked(r, s, v);

        // Accept first offer
        vm.prank(seller);
        market.acceptCollectionOffer(offer1, signature1);

        // Try to replay same signature - should fail
        vm.prank(seller);
        vm.expectRevert(BasePaintMarket.SignatureAlreadyUsed.selector);
        market.acceptCollectionOffer(offer1, signature1);
    }

    // ===========================================
    // FUZZ TEST: Bundle Validation Edge Cases
    // ===========================================

    function testFuzz_PartialBundleAttack(uint256 missingDay) public {
        vm.assume(missingDay >= 1 && missingDay <= 365);

        // Burn the NFT from seller's bundle (setUp mints only 1 of each)
        basePaint.burn(seller, missingDay, 1);

        // Verify seller no longer has the token
        assertEq(basePaint.balanceOf(seller, missingDay), 0, "Token should be burned");

        // Try to create listing - should fail with MissingToken
        vm.prank(seller);
        vm.expectRevert(abi.encodeWithSelector(BasePaintMarket.MissingToken.selector, missingDay));
        market.createListing(BasePaintMarket.BundleType.YEAR_1, 5 ether, DEFAULT_DURATION);
    }

    // ===========================================
    // FUZZ TEST: Reentrancy with Malicious Receiver
    // ===========================================

    function testFuzz_ReentrancyProtection(uint256 listingPrice) public {
        // Bound price to valid range
        listingPrice = bound(listingPrice, MIN_LISTING_PRICE, 100 ether);

        // Verify seller has all tokens (sanity check)
        assertGe(basePaint.balanceOf(seller, 1), 1, "Seller should have token 1");

        // Get next listing ID (staticcall, doesn't consume prank)
        uint256 listingId = market.nextListingId();

        // Create listing from seller (use startPrank to ensure seller context)
        vm.startPrank(seller);
        market.createListing(BasePaintMarket.BundleType.YEAR_1, listingPrice, DEFAULT_DURATION);
        vm.stopPrank();

        // Deploy malicious contract that tries reentrancy
        MaliciousReceiver malicious = new MaliciousReceiver(market, listingId);
        vm.deal(address(malicious), listingPrice * 3);

        // The malicious contract will receive ETH as refund and try to re-enter
        // We send extra ETH to trigger a refund which calls receive()
        // The reentrant call in receive() should fail

        // Try attack with extra ETH to trigger refund
        // The attack flow:
        // 1. MaliciousReceiver.attack() calls buyListing()
        // 2. buyListing transfers NFTs to MaliciousReceiver
        // 3. buyListing tries to send ETH to seller
        // 4. Seller receives ETH, then refund is sent to MaliciousReceiver
        // 5. MaliciousReceiver.receive() tries to call buyListing() again
        // 6. ReentrancyGuard blocks the reentrant call!
        // 7. The whole transaction reverts with TransferFailed (ETH send failed)
        //
        // This proves the contract is properly protected against reentrancy attacks!
        vm.expectRevert(BasePaintMarket.TransferFailed.selector);
        malicious.attack{value: listingPrice * 2}();
    }

    // ===========================================
    // FUZZ TEST: Fee Extraction Attack
    // ===========================================

    function testFuzz_FeeCalculationCorrectness(uint256 price, uint256 feePercent) public {
        // Bound inputs instead of assume to avoid rejection
        price = bound(price, MIN_LISTING_PRICE, 1000 ether);
        feePercent = bound(feePercent, 1, 1000); // Min 0.01%, Max 10%

        // Set custom fee
        vm.prank(owner);
        market.setPlatformFee(feePercent);

        // Create listing
        vm.prank(seller);
        market.createListing(BasePaintMarket.BundleType.YEAR_1, price, DEFAULT_DURATION);

        // Give buyer enough ETH
        vm.deal(buyer, price);

        uint256 sellerBalanceBefore = seller.balance;
        uint256 platformFeesBefore = market.platformFeesAccumulated();

        vm.prank(buyer);
        market.buyListing{value: price}(1);

        // Verify correct fee distribution
        uint256 expectedFee = (price * feePercent) / 10000;
        uint256 expectedSellerAmount = price - expectedFee;

        assertEq(seller.balance - sellerBalanceBefore, expectedSellerAmount, "Seller received wrong amount");
        assertEq(market.platformFeesAccumulated() - platformFeesBefore, expectedFee, "Platform fee incorrect");
    }

    // ===========================================
    // FUZZ TEST: WETH Allowance Manipulation
    // ===========================================

    function testFuzz_WETHAllowanceRaceCondition(uint256 offerPrice, uint256 actualAllowance) public {
        vm.assume(offerPrice > 0 && offerPrice <= 10 ether);
        vm.assume(actualAllowance < offerPrice);

        // Setup buyer with WETH but insufficient allowance
        vm.deal(buyer, 20 ether);
        vm.startPrank(buyer);
        weth.deposit{value: 20 ether}();
        weth.approve(address(market), actualAllowance); // Less than offer
        vm.stopPrank();

        // Create offer
        uint256 nonce = market.offerNonces(buyer);
        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: buyer,
            bundleType: BasePaintMarket.BundleType.YEAR_1,
            price: offerPrice,
            expiresAt: block.timestamp + 1 days,
            salt: 123456,
            nonce: nonce
        });

        // Sign offer
        bytes32 structHash = keccak256(
            abi.encode(
                market.COLLECTION_OFFER_TYPEHASH(),
                offer.buyer,
                offer.bundleType,
                offer.price,
                offer.expiresAt,
                offer.salt,
                offer.nonce
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(buyerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Try to accept - should fail due to insufficient allowance
        vm.prank(seller);
        vm.expectRevert(BasePaintMarket.InsufficientWETHAllowance.selector);
        market.acceptCollectionOffer(offer, signature);
    }

    // ===========================================
    // FUZZ TEST: Upgrade Authorization
    // ===========================================

    function testFuzz_UnauthorizedUpgrade(address randomAttacker) public {
        vm.assume(randomAttacker != address(0) && randomAttacker != owner);

        // Deploy new implementation
        BasePaintMarket newImplementation = new BasePaintMarket();

        // Try to upgrade as non-owner - should fail
        vm.prank(randomAttacker);
        vm.expectRevert("Ownable: caller is not the owner");
        (bool success,) =
            address(market).call(abi.encodeWithSignature("upgradeTo(address)", address(newImplementation)));
        assertFalse(success);
    }

    // ===========================================
    // FUZZ TEST: Timestamp Manipulation
    // ===========================================

    function testFuzz_TimestampExploits(uint256 timestamp, uint256 warpTime) public {
        vm.assume(timestamp > block.timestamp);
        vm.assume(warpTime > 0 && warpTime < 365 days);

        // Setup buyer
        vm.deal(buyer, 10 ether);
        vm.startPrank(buyer);
        weth.deposit{value: 10 ether}();
        weth.approve(address(market), type(uint256).max);
        vm.stopPrank();

        // Create offer with future expiration
        uint256 nonce = market.offerNonces(buyer);
        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: buyer,
            bundleType: BasePaintMarket.BundleType.YEAR_1,
            price: 5 ether,
            expiresAt: timestamp,
            salt: 999,
            nonce: nonce
        });

        // Sign offer
        bytes32 structHash = keccak256(
            abi.encode(
                market.COLLECTION_OFFER_TYPEHASH(),
                offer.buyer,
                offer.bundleType,
                offer.price,
                offer.expiresAt,
                offer.salt,
                offer.nonce
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(buyerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Warp time forward
        vm.warp(block.timestamp + warpTime);

        // Try to accept offer
        vm.prank(seller);
        if (block.timestamp > timestamp) {
            // Should fail if expired
            vm.expectRevert(BasePaintMarket.OfferExpired.selector);
            market.acceptCollectionOffer(offer, signature);
        } else {
            // Should succeed if not expired
            market.acceptCollectionOffer(offer, signature);
        }
    }

    // ===========================================
    // HELPER FUNCTIONS
    // ===========================================

    /// @dev Compute EIP-712 digest locally (replaces market.hashTypedDataV4)
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domainSeparator = _buildDomainSeparator();
        return MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
    }

    /// @dev Build domain separator matching the market contract
    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("BasePaintMarket")),
                keccak256(bytes("1")),
                block.chainid,
                address(market)
            )
        );
    }
}

// Malicious contract for reentrancy testing
contract MaliciousReceiver {
    BasePaintMarket public market;
    uint256 public listingId;
    bool public attacking;

    constructor(BasePaintMarket _market, uint256 _listingId) {
        market = _market;
        listingId = _listingId;
    }

    function attack() external payable {
        attacking = true;
        market.buyListing{value: msg.value}(listingId);
    }

    receive() external payable {
        if (attacking) {
            attacking = false;
            // Try reentrancy
            market.buyListing{value: msg.value}(listingId);
        }
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }
}
