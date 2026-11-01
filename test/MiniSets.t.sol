// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/BasePaintMarket.sol";
import "../src/mocks/MockBasePaint.sol";
import "../src/mocks/MockWETH.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/// @notice v1.13 mini-set + audit-batch tests. Year-bundle behaviour is covered
///         by BasePaintMarket.t.sol; this file focuses on the new surface.
///         Range helpers are read via the public `getBundleDayRange` /
///         `getBundleTokenIds` wrappers (no test harness needed).
contract MiniSetsTest is Test {
    BasePaintMarket public market;
    MockBasePaint public basePaint;
    MockWETH public weth;

    address public owner = address(1);
    address public seller = address(2);
    uint256 public buyerPk = 0xB0B;
    address public buyer;

    uint256 constant MINI_FLOOR = 0.1 ether;
    uint256 constant YEAR_FLOOR = 1 ether;
    uint256 constant DURATION = 30 days;

    BasePaintMarket.BundleType constant M1 = BasePaintMarket.BundleType.MINI_1;
    BasePaintMarket.BundleType constant Y1 = BasePaintMarket.BundleType.YEAR_1;

    function setUp() public {
        buyer = vm.addr(buyerPk);
        basePaint = new MockBasePaint();
        weth = new MockWETH();

        BasePaintMarket impl = new BasePaintMarket();
        bytes memory initData =
            abi.encodeWithSelector(BasePaintMarket.initialize.selector, address(basePaint), address(weth), owner);
        market = BasePaintMarket(payable(address(new ERC1967Proxy(address(impl), initData))));

        vm.prank(owner);
        market.initializeV13(MINI_FLOOR); // reinitializer(2)

        vm.deal(buyer, 100 ether);
        vm.prank(buyer);
        weth.deposit{value: 20 ether}();
    }

    // ---- helpers ----------------------------------------------------------

    function _mintRange(address to, uint256 start, uint256 end) internal {
        for (uint256 d = start; d <= end; d++) {
            basePaint.mint(to, d, 1);
        }
    }

    function _list(address s, BasePaintMarket.BundleType bt, uint256 price) internal returns (uint256) {
        vm.startPrank(s);
        basePaint.setApprovalForAll(address(market), true);
        market.createListing(bt, price, DURATION);
        vm.stopPrank();
        return market.nextListingId() - 1;
    }

    function _signOffer(BasePaintMarket.CollectionOfferParams memory offer, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
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
        bytes32 digest = _eip712Digest(structHash);
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, digest);
        return abi.encodePacked(r, ss, v);
    }

    function _eip712Digest(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("BasePaintMarket"),
                keccak256("1"),
                block.chainid,
                address(market)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    // ---- 1. Enum index pins (append-only invariant) -----------------------

    /// @dev Audit F3 (2026-06-19): pin ALL 26 indices, not just the 6 boundary
    ///      ones. A reorder of any interior mini (e.g. MINI_5 <-> MINI_6) would
    ///      silently corrupt every persisted listing/offer/event for those types;
    ///      the spot-check missed that. Every named value is pinned to its index.
    function test_EnumIndexPins() public pure {
        assertEq(uint8(BasePaintMarket.BundleType.YEAR_1), 0);
        assertEq(uint8(BasePaintMarket.BundleType.YEAR_2), 1);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_1), 2);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_2), 3);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_3), 4);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_4), 5);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_5), 6);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_6), 7);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_7), 8);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_8), 9);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_9), 10);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_10), 11);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_11), 12);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_12), 13);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_13), 14);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_14), 15);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_15), 16);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_16), 17);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_17), 18);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_18), 19);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_19), 20);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_20), 21);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_21), 22);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_22), 23);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_23), 24);
        assertEq(uint8(BasePaintMarket.BundleType.MINI_24), 25);
    }

    // ---- 2. _rangeForBundle exhaustive oracle -----------------------------

    function test_RangeForBundle_Oracle() public view {
        // Pinned to the shared repo-root oracle (bundle-oracle.json) — the SAME
        // file the backend (config/bundles) and frontend (lib/bundles) test
        // suites read. If the contract's _rangeForBundle drifts from that oracle,
        // this fails; all three layers derive their day-ranges from one source.
        // (fs read allow-listed in foundry.toml.)
        string memory json = vm.readFile("bundle-oracle.json");
        for (uint256 i = 0; i < 26; i++) {
            string memory base = string.concat(".bundles[", vm.toString(i), "]");
            uint256 oStart = vm.parseJsonUint(json, string.concat(base, ".start"));
            uint256 oEnd = vm.parseJsonUint(json, string.concat(base, ".end"));

            (uint256 s, uint256 e) = market.getBundleDayRange(BasePaintMarket.BundleType(i));
            assertEq(s, oStart, "start");
            assertEq(e, oEnd, "end");
            uint256 days_ = e - s + 1;
            if (i <= 1) {
                assertEq(days_, 365, "year days");
            } else if (i == 13 || i == 25) {
                assertEq(days_, 35, "closing mini days");
            } else {
                assertEq(days_, 30, "mini days");
            }
        }
    }

    // ---- 3. Coverage: the 12 minis tile each year exactly -----------------

    function test_MinisTileYearExactly() public view {
        // Year 1: MINI_1..MINI_12 cover days 1..365 contiguously, no gap/overlap.
        uint256 expected = 1;
        for (uint256 m = 2; m <= 13; m++) {
            // enum idx 2..13 = MINI_1..MINI_12
            (uint256 s, uint256 e) = market.getBundleDayRange(BasePaintMarket.BundleType(m));
            assertEq(s, expected, "Y1 contiguous start");
            expected = e + 1;
        }
        assertEq(expected, 366, "Y1 covers through 365");

        // Year 2: MINI_13..MINI_24 (enum idx 14..25) cover days 366..730.
        expected = 366;
        for (uint256 m = 14; m <= 25; m++) {
            (uint256 s, uint256 e) = market.getBundleDayRange(BasePaintMarket.BundleType(m));
            assertEq(s, expected, "Y2 contiguous start");
            expected = e + 1;
        }
        assertEq(expected, 731, "Y2 covers through 730");
    }

    // ---- 4. getBundleTokenIds count + endpoints ---------------------------

    function test_GetBundleTokenIds_M4() public view {
        uint256[] memory ids = market.getBundleTokenIds(BasePaintMarket.BundleType.MINI_4);
        assertEq(ids.length, 30);
        assertEq(ids[0], 91);
        assertEq(ids[29], 120);
    }

    // ---- 5. Mini listing happy path ---------------------------------------

    function test_MiniListing_BuyHappyPath() public {
        _mintRange(seller, 1, 30); // MINI_1 = days 1-30
        uint256 id = _list(seller, M1, 0.2 ether);

        uint256 sellerBefore = seller.balance;
        vm.prank(buyer);
        market.buyListing{value: 0.2 ether}(id);

        assertEq(basePaint.balanceOf(buyer, 1), 1, "buyer got day 1");
        assertEq(basePaint.balanceOf(buyer, 30), 1, "buyer got day 30");
        assertGt(seller.balance, sellerBefore, "seller paid");
    }

    // ---- 6. Mini validation: missing day reverts --------------------------

    function test_MiniListing_MissingDay_Reverts() public {
        _mintRange(seller, 1, 29); // missing day 30
        vm.startPrank(seller);
        basePaint.setApprovalForAll(address(market), true);
        vm.expectRevert(abi.encodeWithSelector(BasePaintMarket.MissingToken.selector, 30));
        market.createListing(M1, 0.2 ether, DURATION);
        vm.stopPrank();
    }

    // ---- 7. Per-category minimum price ------------------------------------

    function test_PerCategoryMin() public {
        _mintRange(seller, 1, 30); // MINI_1
        _mintRange(seller, 1, 365); // YEAR_1 too (overlaps, fine)
        vm.startPrank(seller);
        basePaint.setApprovalForAll(address(market), true);

        // mini below 0.1 reverts
        vm.expectRevert(BasePaintMarket.PriceTooLow.selector);
        market.createListing(M1, 0.05 ether, DURATION);
        // mini at floor ok
        market.createListing(M1, MINI_FLOOR, DURATION);

        // year below 1 ETH reverts (even though > mini floor)
        vm.expectRevert(BasePaintMarket.PriceTooLow.selector);
        market.createListing(Y1, 0.5 ether, DURATION);
        // year at 1 ETH ok
        market.createListing(Y1, YEAR_FLOOR, DURATION);
        vm.stopPrank();
    }

    // ---- 8. Overlap (D1): year + mini from same NFTs, first buy wins ------

    function test_Overlap_FirstBuyWins() public {
        _mintRange(seller, 1, 365); // backs both YEAR_1 and MINI_1
        uint256 yearId = _list(seller, Y1, 2 ether);
        uint256 miniId = _list(seller, M1, 0.2 ether);

        // Buy the mini first → seller loses days 1-30
        vm.prank(buyer);
        market.buyListing{value: 0.2 ether}(miniId);
        assertEq(basePaint.balanceOf(buyer, 1), 1);

        // The year listing is now unfulfillable (seller no longer owns day 1)
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(BasePaintMarket.MissingToken.selector, 1));
        market.buyListing{value: 2 ether}(yearId);
    }

    // ---- 9. Independent per-type listings coexist -------------------------

    function test_IndependentPerTypeListings() public {
        _mintRange(seller, 1, 365);
        uint256 yearId = _list(seller, Y1, 2 ether);
        uint256 miniId = _list(seller, M1, 0.2 ether);
        assertTrue(yearId != miniId);
        assertEq(market.activeListingByUser(seller, Y1), yearId);
        assertEq(market.activeListingByUser(seller, M1), miniId);
    }

    // ---- 10. Offer for a mini (unchanged EIP-712 typehash) ----------------

    function test_OfferForMini() public {
        _mintRange(seller, 1, 30);
        vm.prank(seller);
        basePaint.setApprovalForAll(address(market), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: buyer,
            bundleType: M1,
            price: 0.3 ether,
            expiresAt: block.timestamp + 7 days,
            salt: 1,
            nonce: market.offerNonces(buyer)
        });
        vm.prank(buyer);
        weth.approve(address(market), 0.3 ether);
        bytes memory sig = _signOffer(offer, buyerPk);

        vm.prank(seller);
        market.acceptCollectionOffer(offer, sig);

        assertEq(basePaint.balanceOf(buyer, 1), 1);
        assertEq(basePaint.balanceOf(buyer, 30), 1);
    }

    // ---- 11. M-02: offer expiring too far out reverts ---------------------

    function test_M02_OfferTooLong() public {
        _mintRange(seller, 1, 30);
        vm.prank(seller);
        basePaint.setApprovalForAll(address(market), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: buyer,
            bundleType: M1,
            price: 0.3 ether,
            expiresAt: block.timestamp + 91 days, // > MAX_OFFER_DURATION
            salt: 2,
            nonce: market.offerNonces(buyer)
        });
        vm.prank(buyer);
        weth.approve(address(market), 0.3 ether);
        bytes memory sig = _signOffer(offer, buyerPk);

        vm.prank(seller);
        vm.expectRevert(BasePaintMarket.OfferTooLong.selector);
        market.acceptCollectionOffer(offer, sig);
    }

    // ---- 12. L-01: min-price sanity bounds on both setters ----------------

    function test_L01_MinPriceBounds() public {
        vm.startPrank(owner);
        vm.expectRevert(BasePaintMarket.InvalidMinPrice.selector);
        market.setMinListingPrice(0.0001 ether); // below MIN_FLOOR_BOUND
        vm.expectRevert(BasePaintMarket.InvalidMinPrice.selector);
        market.setMinListingPrice(2000 ether); // above MAX_FLOOR_BOUND
        vm.expectRevert(BasePaintMarket.InvalidMinPrice.selector);
        market.setMinMiniListingPrice(0.0001 ether);
        // in-range ok
        market.setMinListingPrice(2 ether);
        market.setMinMiniListingPrice(0.05 ether);
        vm.stopPrank();
        assertEq(market.minListingPrice(), 2 ether);
        assertEq(market.minMiniListingPrice(), 0.05 ether);
    }

    // ---- 13. L-03: cleanup works while paused -----------------------------

    function test_L03_CleanupWhilePaused() public {
        _mintRange(seller, 1, 30);
        uint256 id = _list(seller, M1, 0.2 ether);

        vm.warp(block.timestamp + DURATION + 1); // expire it
        vm.prank(owner);
        market.pause("test");

        // cleanup must still work while paused
        market.cleanupExpiredListing(id);
        (,,,, bool active,) = market.listings(id);
        assertFalse(active);
    }

    // ---- 13b. Pause matrix: mini-set buy reverts while paused --------------
    // Same `whenNotPaused` gate as year bundles (BasePaintMarket.t.sol); pinned
    // here because mini listings share the buy path but have their own floor.

    function test_BuyListing_RevertIf_Paused() public {
        _mintRange(seller, 1, 30);
        uint256 id = _list(seller, M1, 0.2 ether);

        vm.prank(owner);
        market.pause("test");

        vm.prank(buyer);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        market.buyListing{value: 0.2 ether}(id);

        (,,,, bool active,) = market.listings(id);
        assertTrue(active); // listing survives the pause
    }

    // ---- 14. reinitializer can't re-run -----------------------------------

    function test_Reinitializer_CannotRerun() public {
        vm.prank(owner);
        vm.expectRevert(); // Initializable: already initialized (version 2 consumed)
        market.initializeV13(0.2 ether);
    }

    /// @dev Audit SC-6 (2026-07-24): reinitializers have no `onlyOwner`. Not
    ///      exploitable on v1.13 — `reinitializer(2)` is exhausted, so even a
    ///      non-owner call reverts. Pinned so the pattern is regression-tested
    ///      for future upgrade versions.
    function test_InitializeV13_RevertIf_NonOwner() public {
        vm.prank(seller); // any non-owner
        vm.expectRevert(); // Initializable: version 2 already consumed
        market.initializeV13(0.2 ether);
    }
}
