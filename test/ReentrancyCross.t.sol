// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/BasePaintMarket.sol";
import "../src/mocks/MockBasePaint.sol";
import "../src/mocks/MockWETH.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title ReentrancyCrossTest
 * @notice Cross-function reentrancy tests driven from ERC-1155 receive hooks.
 *
 * Closes audit 2026-07-24 §1.4 test gap: the existing MaliciousReceiver
 * (test/BasePaintMarketFuzz.t.sol) only re-enters `buyListing` via the ETH
 * refund path. These tests instead attack the UNPROTECTED (non-`nonReentrant`)
 * functions — createListing, cancelListing, cancelAllOffers, cleanupExpired* —
 * from `onERC1155BatchReceived` inside both trade paths:
 *
 *   1. acceptCollectionOffer (WETH path): v1.13 (M-01) moved ALL WETH movements
 *      + fee accounting BEFORE the NFT transfer, so the buyer's callback must
 *      observe a fully-settled deal. Verified via in-callback ghost snapshots.
 *   2. buyListing (ETH path): the listing is cleared BEFORE the NFT transfer,
 *      while payment deliberately happens AFTER it (seller ETH callback would
 *      otherwise self-DoS the sale). The callback must observe exactly that,
 *      and the only thing standing between the callback and fund movement is
 *      `nonReentrant` on the trade functions plus the already-cleared state.
 *
 * Each test asserts concrete safety properties (funds moved exactly once,
 * listing state consistent, foreign listing not cancellable, consumed digest
 * stays consumed) — not just "the transaction did not revert".
 */
contract ReentrancyCrossTest is Test {
    BasePaintMarket public market;
    MockBasePaint public basePaint;
    MockWETH public weth;

    address public owner = address(1);
    address public seller = address(2);
    address public seller2 = address(3);
    uint256 public signerKey = 0xC0FFEE; // EOA controlling the attacker's EIP-1271 wallet
    address public signer;

    uint256 constant OFFER_PRICE = 10 ether;

    function setUp() public {
        signer = vm.addr(signerKey);

        basePaint = new MockBasePaint();
        weth = new MockWETH();

        BasePaintMarket implementation = new BasePaintMarket();
        bytes memory initData =
            abi.encodeWithSelector(BasePaintMarket.initialize.selector, address(basePaint), address(weth), owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        market = BasePaintMarket(payable(address(proxy)));

        for (uint256 i = 1; i <= 730; i++) {
            basePaint.mint(seller, i, 1);
            basePaint.mint(seller2, i, 1);
        }
        vm.prank(seller);
        basePaint.setApprovalForAll(address(market), true);
        vm.prank(seller2);
        basePaint.setApprovalForAll(address(market), true);
    }

    // ===========================================
    // WETH path: callback inside acceptCollectionOffer
    // ===========================================

    function test_CrossFunctionReentrancy_FromAcceptCollectionOfferCallback() public {
        // Seller has an ACTIVE listing for the same bundle the offer targets, so
        // acceptCollectionOffer cancels it mid-flight (the ListingCancelled path)
        // before the NFT transfer — the callback must observe it already gone.
        vm.prank(seller);
        market.createListing(BasePaintMarket.BundleType.YEAR_1, 12 ether, 30 days);
        uint256 sellerListingId = market.activeListingByUser(seller, BasePaintMarket.BundleType.YEAR_1);

        CrossFunctionReenterer attacker = new CrossFunctionReenterer(market, basePaint, weth, signer);
        vm.deal(address(attacker), 30 ether);
        attacker.fundWeth(OFFER_PRICE);
        attacker.approveMarket();
        attacker.arm(BasePaintMarket.BundleType.YEAR_1, sellerListingId, OFFER_PRICE, seller);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: address(attacker),
            bundleType: BasePaintMarket.BundleType.YEAR_1,
            price: OFFER_PRICE,
            expiresAt: block.timestamp + 1 days,
            salt: 42,
            nonce: market.offerNonces(address(attacker))
        });
        bytes memory signature = _signOffer(offer);

        uint256 fee = (OFFER_PRICE * market.platformFee()) / 10000;
        uint256 sellerAmount = OFFER_PRICE - fee;
        uint256 feesBefore = market.platformFeesAccumulatedWETH();
        uint256 sellerWethBefore = weth.balanceOf(seller);

        vm.prank(seller);
        market.acceptCollectionOffer(offer, signature);

        // --- Callback fired and observed a FULLY SETTLED deal (v1.13 M-01 ordering) ---
        assertTrue(attacker.callbackFired(), "callback did not fire");
        assertTrue(attacker.ownedBundleInCallback(), "buyer must hold the bundle when the callback runs");
        assertEq(attacker.feesWethSeenInCallback(), feesBefore + fee, "WETH fee must be booked BEFORE the NFT callback");
        assertEq(
            attacker.sellerWethSeenInCallback(), sellerWethBefore + sellerAmount, "seller paid BEFORE the NFT callback"
        );
        assertFalse(attacker.listingActiveSeenInCallback(), "seller listing must be cancelled BEFORE the NFT callback");

        // --- Cross-function attempts: no exploit effect ---
        assertFalse(attacker.reenterBuySucceeded(), "re-entering buyListing must fail (nonReentrant)");
        assertFalse(attacker.cancelListingSucceeded(), "attacker cannot cancel another user's listing");
        assertFalse(attacker.cleanupSucceeded(), "cleanup of an inactive listing must revert");
        // cancelAllOffers is intentionally unprotected, but it only bumps the
        // caller's own nonce — the attacker hurts nobody but itself.
        assertTrue(attacker.cancelAllOffersSucceeded(), "cancelAllOffers bumps only the attacker's own nonce");
        assertEq(market.offerNonces(address(attacker)), 1, "attacker nonce bumped by its own cancelAllOffers");
        // createListing succeeds — legitimately: at callback time the attacker
        // already owns the bundle, so this is identical to listing it in the
        // next transaction. The safety property is pointer/state consistency.
        assertTrue(attacker.createListingSucceeded(), "post-transfer re-list is a legitimate action");
        uint256 relistedId = attacker.createdListingId();
        (address relistSeller,,,, bool relistActive,) = market.listings(relistedId);
        assertEq(relistSeller, address(attacker), "re-listed listing must belong to the attacker");
        assertTrue(relistActive);
        assertEq(
            market.activeListingByUser(address(attacker), BasePaintMarket.BundleType.YEAR_1),
            relistedId,
            "re-list pointer inconsistent"
        );

        // --- Funds moved EXACTLY once ---
        assertEq(market.platformFeesAccumulatedWETH(), feesBefore + fee, "WETH fee booked more/less than once");
        assertEq(weth.balanceOf(seller), sellerWethBefore + sellerAmount, "seller WETH proceeds wrong");
        assertEq(weth.balanceOf(address(attacker)), 0, "buyer WETH not fully spent");

        // --- Deal-side state is consistent ---
        (,,,, bool sellerListingActive,) = market.listings(sellerListingId);
        assertFalse(sellerListingActive, "cancelled seller listing resurrected");
        assertEq(market.activeListingByUser(seller, BasePaintMarket.BundleType.YEAR_1), 0, "seller pointer not cleared");
        assertEq(basePaint.balanceOf(seller, 1), 0, "seller still holds a sold token");
        assertEq(basePaint.balanceOf(address(attacker), 1), 1, "buyer did not receive the bundle");

        // --- Replay protection: the consumed digest stays consumed ---
        assertTrue(market.isSignatureUsed(_offerDigest(offer)), "digest not marked used");
        // A second accept of the same signed offer reverts: the callback's
        // cancelAllOffers already bumped the buyer nonce (OfferNonceMismatch),
        // and the digest is consumed anyway (asserted above).
        vm.prank(seller2);
        vm.expectRevert();
        market.acceptCollectionOffer(offer, signature);
    }

    // ===========================================
    // ETH path: callback inside buyListing
    // ===========================================

    function test_CrossFunctionReentrancy_FromBuyListingCallback() public {
        uint256 price = 10 ether;
        vm.prank(seller);
        market.createListing(BasePaintMarket.BundleType.YEAR_1, price, 30 days);
        uint256 listingId = market.activeListingByUser(seller, BasePaintMarket.BundleType.YEAR_1);

        CrossFunctionReenterer attacker = new CrossFunctionReenterer(market, basePaint, weth, signer);
        vm.deal(address(attacker), 25 ether);
        attacker.approveMarket();
        attacker.arm(BasePaintMarket.BundleType.YEAR_1, listingId, price, seller);

        uint256 fee = (price * market.platformFee()) / 10000;
        uint256 feesBefore = market.platformFeesAccumulated();
        uint256 sellerEthBefore = seller.balance;

        // Overpay by 2 ether to also exercise the refund path (plain receive(),
        // no attack there — refund re-entry is covered by MaliciousReceiver).
        attacker.buy(listingId, price + 2 ether);

        // --- Callback observed the ETH-path ordering: listing already cleared,
        //     funds NOT yet moved (payment is deliberately AFTER the NFT transfer) ---
        assertTrue(attacker.callbackFired(), "callback did not fire");
        assertTrue(attacker.ownedBundleInCallback(), "buyer must hold the bundle when the callback runs");
        assertFalse(attacker.listingActiveSeenInCallback(), "listing must be cleared BEFORE the NFT transfer");
        assertEq(
            attacker.sellerEthSeenInCallback(),
            sellerEthBefore,
            "ETH path pays the seller AFTER the NFT callback (deliberate, v1.13)"
        );
        assertEq(attacker.feesEthSeenInCallback(), feesBefore, "ETH fee must not be booked before the NFT callback");

        // --- Cross-function attempts: no exploit effect ---
        assertFalse(attacker.reenterBuySucceeded(), "re-entering buyListing must fail (nonReentrant)");
        assertFalse(
            attacker.cancelListingSucceeded(), "attacker cannot cancel the listing (not seller; already cleared)"
        );
        assertFalse(attacker.cleanupSucceeded(), "cleanup of an inactive listing must revert");
        assertTrue(attacker.cancelAllOffersSucceeded(), "cancelAllOffers bumps only the attacker's own nonce");
        assertTrue(attacker.createListingSucceeded(), "post-transfer re-list is a legitimate action");
        uint256 relistedId = attacker.createdListingId();
        (address relistSeller,,,, bool relistActive,) = market.listings(relistedId);
        assertEq(relistSeller, address(attacker), "re-listed listing must belong to the attacker");
        assertTrue(relistActive);

        // --- Funds moved EXACTLY once; overpayment refunded exactly once ---
        assertEq(market.platformFeesAccumulated(), feesBefore + fee, "ETH fee booked more/less than once");
        assertEq(seller.balance, sellerEthBefore + (price - fee), "seller ETH proceeds wrong");
        assertEq(address(attacker).balance, 25 ether - price, "refund not returned exactly once");

        // --- Listing state consistent ---
        (,,,, bool active,) = market.listings(listingId);
        assertFalse(active, "sold listing still active");
        assertEq(market.activeListingByUser(seller, BasePaintMarket.BundleType.YEAR_1), 0, "seller pointer not cleared");
        assertEq(basePaint.balanceOf(seller, 1), 0, "seller still holds a sold token");
        assertEq(basePaint.balanceOf(address(attacker), 1), 1, "buyer did not receive the bundle");
    }

    // ===== Helpers =====

    function _signOffer(BasePaintMarket.CollectionOfferParams memory offer) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, _offerDigest(offer));
        return abi.encodePacked(r, s, v);
    }

    function _offerDigest(BasePaintMarket.CollectionOfferParams memory offer) internal view returns (bytes32) {
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
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _domainSeparator() internal view returns (bytes32) {
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

/**
 * @title CrossFunctionReenterer
 * @notice Attacking buyer contract. Acts as an EIP-1271 smart wallet (so it can
 *         be the `buyer` of a collection offer) and, from its ERC-1155 batch
 *         receive hook, fires cross-function calls at the market while the
 *         outer trade is mid-flight. Records ghost snapshots of the state it
 *         observed plus the success/failure of every attempt, which the test
 *         asserts against.
 */
contract CrossFunctionReenterer {
    BasePaintMarket public immutable market;
    MockBasePaint public immutable basePaint;
    MockWETH public immutable weth;
    address public immutable signer; // EOA whose ECDSA signatures this wallet accepts

    uint256 constant RELIST_PRICE = 5 ether;
    uint256 constant RELIST_DURATION = 30 days;

    // Arm parameters (single-shot).
    bool public armed;
    BasePaintMarket.BundleType public armBundleType;
    uint256 public armListingId;
    uint256 public armReenterValue;
    address public armSeller;

    // Ghost snapshots recorded INSIDE the callback.
    bool public callbackFired;
    bool public listingActiveSeenInCallback;
    bool public ownedBundleInCallback;
    uint256 public feesWethSeenInCallback;
    uint256 public feesEthSeenInCallback;
    uint256 public sellerWethSeenInCallback;
    uint256 public sellerEthSeenInCallback;

    // Outcomes of the cross-function calls attempted from the callback.
    bool public reenterBuySucceeded;
    bool public createListingSucceeded;
    uint256 public createdListingId;
    bool public cancelListingSucceeded;
    bool public cancelAllOffersSucceeded;
    bool public cleanupSucceeded;

    constructor(BasePaintMarket _market, MockBasePaint _basePaint, MockWETH _weth, address _signer) {
        market = _market;
        basePaint = _basePaint;
        weth = _weth;
        signer = _signer;
    }

    receive() external payable {}

    function fundWeth(uint256 amount) external {
        weth.deposit{value: amount}();
    }

    function approveMarket() external {
        basePaint.setApprovalForAll(address(market), true);
        weth.approve(address(market), type(uint256).max);
    }

    function arm(BasePaintMarket.BundleType bundleType, uint256 listingId, uint256 reenterValue, address seller_)
        external
    {
        armed = true;
        armBundleType = bundleType;
        armListingId = listingId;
        armReenterValue = reenterValue;
        armSeller = seller_;
    }

    /// @dev Spends THIS contract's own balance (not fresh msg.value) so the
    ///      test can track the attacker's net outlay and the exact refund.
    function buy(uint256 listingId, uint256 amount) external {
        market.buyListing{value: amount}(listingId);
    }

    /// @dev Minimal EIP-1271: a signature is valid iff `signer` signed the hash.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == signer) {
            return this.isValidSignature.selector;
        }
        return bytes4(0xffffffff);
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata ids, uint256[] calldata, bytes calldata)
        external
        returns (bytes4)
    {
        if (!armed) return this.onERC1155BatchReceived.selector;
        armed = false; // single-shot: never recurse on a nested transfer

        callbackFired = true;

        // ---- Ghost snapshots: what state does the callback observe? ----
        ownedBundleInCallback = ids.length > 0 && basePaint.balanceOf(address(this), ids[0]) == 1;
        feesWethSeenInCallback = market.platformFeesAccumulatedWETH();
        feesEthSeenInCallback = market.platformFeesAccumulated();
        sellerWethSeenInCallback = weth.balanceOf(armSeller);
        sellerEthSeenInCallback = armSeller.balance;
        if (armListingId != 0) {
            (,,,, bool active,) = market.listings(armListingId);
            listingActiveSeenInCallback = active;
        }

        // ---- Cross-function attack attempts ----

        // 1. Re-enter the trade path — must revert: buyListing is nonReentrant.
        if (armListingId != 0 && address(this).balance >= armReenterValue) {
            try market.buyListing{value: armReenterValue}(armListingId) {
                reenterBuySucceeded = true;
            } catch {}
        }

        // 2. createListing — NOT nonReentrant. Runs against post-transfer state;
        //    legitimate iff we already own the bundle (asserted by the test).
        try market.createListing(armBundleType, RELIST_PRICE, RELIST_DURATION) {
            createListingSucceeded = true;
            createdListingId = market.activeListingByUser(address(this), armBundleType);
        } catch {}

        if (armListingId != 0) {
            // 3. cancelListing on another user's / already-cleared listing — must revert.
            try market.cancelListing(armListingId) {
                cancelListingSucceeded = true;
            } catch {}

            // 4. cleanupExpiredListing on a non-expired / inactive listing — must revert.
            try market.cleanupExpiredListing(armListingId) {
                cleanupSucceeded = true;
            } catch {}
        }

        // 5. cancelAllOffers — NOT nonReentrant by design; succeeds but only
        //    bumps THIS contract's own offer nonce (no effect on the deal).
        try market.cancelAllOffers() {
            cancelAllOffersSucceeded = true;
        } catch {}

        return this.onERC1155BatchReceived.selector;
    }
}
