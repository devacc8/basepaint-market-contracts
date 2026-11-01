// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {BasePaintMarket} from "../../src/BasePaintMarket.sol";
import {MockBasePaint} from "../../src/mocks/MockBasePaint.sol";
import {MockWETH} from "../../src/mocks/MockWETH.sol";

/**
 * @title MarketHandler
 * @notice Bounded action set for stateful invariant fuzzing of BasePaintMarket.
 *
 * Why a custom Handler is needed:
 *   Foundry's default open-fuzzing would call every external function with random calldata
 *   and random `msg.sender`. For this marketplace that produces ~100% reverts:
 *     - createListing requires the caller to own a full 365-token bundle + approval
 *     - buyListing requires an active listing and msg.value >= price
 *     - acceptCollectionOffer requires a valid EIP-712 signature from a buyer with WETH
 *   We constrain actions to a small set of pre-funded sellers/buyers cycling through all
 *   26 bundle types (2 years + 24 minis, F6 2026-06-19) — this lets the fuzzer reach
 *   the year<->mini overlap state (one sale strands a sibling listing), plus meaningful
 *   states (multiple sales,
 *   accumulated fees, mid-flight cancels) instead of bouncing off precondition checks.
 *
 * Admin actions (audit 2026-07-24 §1.4): the handler also sequences owner
 * pause/unpause, setPlatformFee (≤ MAX_PLATFORM_FEE) and blacklist add/remove,
 * so invariants I1–I6 are checked under changing admin state. None of these
 * weaken an invariant: pause/blacklist move no funds and clear no state (see
 * per-action comments), they only make some trade actions revert, which the
 * actions' try/catch already tolerates.
 *
 * Invariants verified by the parent test (Invariants.t.sol):
 *   I1. address(market).balance >= platformFeesAccumulated
 *   I2. weth.balanceOf(market) >= platformFeesAccumulatedWETH
 *   I3. platformFee <= MAX_PLATFORM_FEE (1000 bps = 10%)
 *   I4. activeListingByUser[seller][bt] points to a listing that is active OR is 0
 *   I5. NFT custody — market.balanceOf for every tracked tokenId is 0 (approval-based design)
 *   I6. Replay protection — once usedSignatures[digest] is true it never returns to false
 *
 * NOTE: ghost variables here (`acceptedDigests`, `ghostFeesPaidEth`, `ghostFeesPaidWeth`)
 *       only TRACK successful actions for assertion-side ghost checks. The Handler itself
 *       performs no math the contract isn't already doing.
 */
contract MarketHandler is Test {
    BasePaintMarket public immutable market;
    MockBasePaint public immutable basePaint;
    MockWETH public immutable weth;

    // Bounded actor pools — fuzzer indexes into these via msg.sender modulo length.
    address[3] public sellers;
    address[3] public buyers;
    uint256[3] public buyerKeys;

    // Ghost state for parent-test assertions.
    bytes32[] public acceptedDigests;
    uint256 public ghostFeesPaidEth;
    uint256 public ghostFeesPaidWeth;
    uint256 public callCount;

    constructor(BasePaintMarket _market, MockBasePaint _basePaint, MockWETH _weth) {
        market = _market;
        basePaint = _basePaint;
        weth = _weth;

        // Three sellers, each pre-loaded with BOTH bundles + approval to market.
        // Why both: lets fuzzer rotate bundle types per call without re-seeding.
        sellers[0] = makeAddr("seller-0");
        sellers[1] = makeAddr("seller-1");
        sellers[2] = makeAddr("seller-2");
        for (uint256 s = 0; s < 3; s++) {
            for (uint256 d = 1; d <= 730; d++) {
                basePaint.mint(sellers[s], d, 1);
            }
            vm.prank(sellers[s]);
            basePaint.setApprovalForAll(address(market), true);
        }

        // Three buyers with funded ETH + WETH + approval.
        buyerKeys[0] = 0xB001;
        buyerKeys[1] = 0xB002;
        buyerKeys[2] = 0xB003;
        for (uint256 b = 0; b < 3; b++) {
            buyers[b] = vm.addr(buyerKeys[b]);
            vm.deal(buyers[b], 1000 ether);
            vm.prank(buyers[b]);
            weth.deposit{value: 500 ether}();
            vm.prank(buyers[b]);
            weth.approve(address(market), type(uint256).max);
        }
    }

    // ===== Action 1: createListing =====
    function createListing(uint8 sellerIdx, uint8 bundleIdx, uint256 priceSeed, uint256 durationSeed) external {
        callCount++;
        address seller = sellers[sellerIdx % 3];
        BasePaintMarket.BundleType bt = _bundleFromIdx(bundleIdx);
        // Price in [1 ether, 100 ether] — above minListingPrice, below buyers' funding.
        uint256 price = 1 ether + (priceSeed % 99 ether);
        // Duration in [1 day, 180 days] — within MIN/MAX bounds.
        uint256 duration = 1 days + (durationSeed % (179 days));

        // Skip if seller already has active non-expired listing for this bundle
        // (createListing would revert with DuplicateListing — wastes a fuzz call).
        uint256 existing = market.activeListingByUser(seller, bt);
        if (existing != 0) {
            (,,,, bool active, uint256 expiresAt) = market.listings(existing);
            if (active && block.timestamp <= expiresAt) return;
        }

        // Re-seed bundle if seller previously sold it (mint replenishes 1 per token).
        _ensureBundleOwned(seller, bt);

        vm.prank(seller);
        try market.createListing(bt, price, duration) {} catch {}
    }

    // ===== Action 2: cancelListing =====
    function cancelListing(uint8 sellerIdx, uint8 bundleIdx) external {
        callCount++;
        address seller = sellers[sellerIdx % 3];
        BasePaintMarket.BundleType bt = _bundleFromIdx(bundleIdx);
        uint256 listingId = market.activeListingByUser(seller, bt);
        if (listingId == 0) return;
        vm.prank(seller);
        try market.cancelListing(listingId) {} catch {}
    }

    // ===== Action 3: buyListing =====
    function buyListing(uint8 buyerIdx, uint8 sellerIdx, uint8 bundleIdx) external {
        callCount++;
        address buyer = buyers[buyerIdx % 3];
        address seller = sellers[sellerIdx % 3];
        if (buyer == seller) return; // can't buy own listing
        BasePaintMarket.BundleType bt = _bundleFromIdx(bundleIdx);
        uint256 listingId = market.activeListingByUser(seller, bt);
        if (listingId == 0) return;
        (,, uint256 price,, bool active, uint256 expiresAt) = market.listings(listingId);
        if (!active || block.timestamp > expiresAt) return;
        if (buyer.balance < price) return;

        uint256 feeBefore = market.platformFeesAccumulated();
        vm.prank(buyer);
        try market.buyListing{value: price}(listingId) {
            ghostFeesPaidEth += (market.platformFeesAccumulated() - feeBefore);
        } catch {}
    }

    // ===== Action 4: acceptCollectionOffer =====
    function acceptCollectionOffer(
        uint8 buyerIdx,
        uint8 sellerIdx,
        uint8 bundleIdx,
        uint256 priceSeed,
        uint256 saltSeed
    ) external {
        callCount++;
        address buyer = buyers[buyerIdx % 3];
        uint256 buyerKey = buyerKeys[buyerIdx % 3];
        address seller = sellers[sellerIdx % 3];
        if (buyer == seller) return;
        BasePaintMarket.BundleType bt = _bundleFromIdx(bundleIdx);

        uint256 price = 1 ether + (priceSeed % 50 ether); // bounded under buyer WETH balance
        if (weth.balanceOf(buyer) < price) return;
        _ensureBundleOwned(seller, bt);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: buyer,
            bundleType: bt,
            price: price,
            expiresAt: block.timestamp + 1 days,
            salt: saltSeed,
            nonce: market.offerNonces(buyer)
        });

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

        // EIP-712 digest reconstruction — read DOMAIN_SEPARATOR via cast.
        bytes32 domainSeparator = _domainSeparator();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(buyerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 feeBefore = market.platformFeesAccumulatedWETH();
        vm.prank(seller);
        try market.acceptCollectionOffer(offer, signature) {
            acceptedDigests.push(digest);
            ghostFeesPaidWeth += (market.platformFeesAccumulatedWETH() - feeBefore);
        } catch {}
    }

    // ===== Action 5: cancelAllOffers (nonce bump) =====
    function cancelAllOffers(uint8 buyerIdx) external {
        callCount++;
        address buyer = buyers[buyerIdx % 3];
        vm.prank(buyer);
        try market.cancelAllOffers() {} catch {}
    }

    // ===== Action 6: adminPause (rare) =====
    /// Owner pauses the contract. Gated to ~1/8 of calls so most of the sequence
    /// runs unpaused. While paused, createListing/buyListing/acceptCollectionOffer
    /// revert — absorbed by their try/catch — while cancel*/cleanup stay callable
    /// (deliberate, L-03). Invariants I1–I6 are pause-agnostic: pause moves no
    /// funds and touches no listing/signature state, so nothing to weaken.
    function adminPause(uint8 seed) external {
        callCount++;
        if (seed % 8 != 0) return; // rare: keep the sequence mostly unpaused
        if (market.paused()) return;
        vm.prank(market.owner());
        market.pause("invariant fuzz");
    }

    // ===== Action 7: adminUnpause =====
    /// Runs ungated so a pause never stalls the sequence for long.
    function adminUnpause() external {
        callCount++;
        if (!market.paused()) return;
        vm.prank(market.owner());
        market.unpause();
    }

    // ===== Action 8: adminSetPlatformFee =====
    /// Sets the fee anywhere in [0, MAX_PLATFORM_FEE]. Bounded by the same cap
    /// the contract enforces; I3 asserts the cap holds under admin churn.
    /// A fee change moves no funds (fees are booked at trade time), so I1/I2
    /// remain valid without adjustment. Called directly (no try/catch): a valid
    /// fee being rejected would be a real regression the run should catch.
    function adminSetPlatformFee(uint256 feeSeed) external {
        callCount++;
        uint256 newFee = feeSeed % (market.MAX_PLATFORM_FEE() + 1);
        vm.prank(market.owner());
        market.setPlatformFee(newFee);
    }

    // ===== Action 9: adminSetBlacklist =====
    /// Randomly blacklists/unblacklists a seller or buyer (~75% add / 25% remove,
    /// so some actors are blocked at any time but pools don't stall permanently).
    /// Blacklisting makes that actor's createListing/buyListing/acceptOffer revert
    /// (absorbed by try/catch) but never clears listings, moves funds, or consumes
    /// signatures — cancelListing/cancelAllOffers intentionally remain callable.
    /// Hence I1–I6 need no weakening; the blacklisted-actor case is handled by
    /// the actions' existing revert tolerance, not by relaxing assertions.
    function adminSetBlacklist(uint8 actorIdx, uint8 seed) external {
        callCount++;
        address actor = seed % 2 == 0 ? sellers[actorIdx % 3] : buyers[actorIdx % 3];
        vm.prank(market.owner());
        if (seed % 4 < 3) {
            market.addToBlacklist(actor);
        } else {
            market.removeFromBlacklist(actor);
        }
    }

    // ===== Helpers =====

    /// Map a fuzz seed to ANY of the 26 bundle types (2 years + 24 minis).
    /// Audit F6 (2026-06-19): was `bundleIdx % 2` (years only), so the 24 mini
    /// types and the year<->mini overlap state space got 0% stateful-fuzz
    /// coverage. `% 26` distributes evenly across the full enum (YEAR_1=0 ..
    /// MINI_24=25), letting the fuzzer create overlapping year+mini listings
    /// from one seller and exercise the doomed-sibling sale path.
    function _bundleFromIdx(uint8 bundleIdx) internal pure returns (BasePaintMarket.BundleType) {
        return BasePaintMarket.BundleType(bundleIdx % 26);
    }

    /// Re-mint missing bundle tokens so the seller can list/sell again.
    /// MockBasePaint is mint-on-demand; in prod, NFTs are immutable supply.
    /// Uses the contract's own `getBundleDayRange` (v1.13) so the range is
    /// always correct for any of the 26 types — no duplicated formula.
    function _ensureBundleOwned(address seller, BasePaintMarket.BundleType bt) internal {
        (uint256 start, uint256 end) = market.getBundleDayRange(bt);
        for (uint256 d = start; d <= end; d++) {
            if (basePaint.balanceOf(seller, d) == 0) {
                basePaint.mint(seller, d, 1);
            }
        }
    }

    function _domainSeparator() internal view returns (bytes32) {
        // Re-derive what EIP712Upgradeable.__EIP712_init("BasePaintMarket", "1") produces.
        // Cheaper than reading via a getter — Foundry-only path, gas-irrelevant.
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

    // Ghost views for parent-test assertions.
    function acceptedDigestsLength() external view returns (uint256) {
        return acceptedDigests.length;
    }
}
