// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import {BasePaintMarket} from "../../src/BasePaintMarket.sol";
import {MockBasePaint} from "../../src/mocks/MockBasePaint.sol";
import {MockWETH} from "../../src/mocks/MockWETH.sol";
import {MarketHandler} from "./MarketHandler.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title BasePaintMarketInvariants
 * @notice Stateful fuzz / invariant tests for BasePaintMarket.
 *
 * Closes audit Tests-M-2 (MED-2): "No invariant tests on the contract".
 *
 * Each `invariant_*` is checked AFTER every randomly-sequenced call the fuzzer makes
 * through MarketHandler. With Foundry's default `runs = 256, depth = 500`, that's
 * ~128,000 state transitions verified per invariant per run — far stronger coverage
 * than the existing one-shot fuzz tests in BasePaintMarketFuzz.t.sol.
 *
 * Invariants (mirrors MarketHandler.sol's documentation):
 *   I1: ETH solvency — contract can always pay out accumulated platform fees
 *   I2: WETH solvency — same for WETH
 *   I3: Fee bounds — platformFee never exceeds MAX_PLATFORM_FEE
 *   I4: Active-listing pointer consistency — activeListingByUser is never a dangling reference
 *   I5: No NFT custody — approval-based design holds; market never owns BasePaint NFTs
 *   I6: Replay protection — once a signature digest is consumed it stays consumed
 *
 * If the fuzzer breaks ANY of these, that's a real bug class — exactly what the
 * audit flagged as missing. Eight one-shot fuzz tests cannot rule these out;
 * sequenced fuzzing can.
 */
contract BasePaintMarketInvariants is StdInvariant, Test {
    BasePaintMarket public market;
    MockBasePaint public basePaint;
    MockWETH public weth;
    MarketHandler public handler;

    address public marketOwner = makeAddr("market-owner");

    function setUp() public {
        basePaint = new MockBasePaint();
        weth = new MockWETH();

        BasePaintMarket implementation = new BasePaintMarket();
        bytes memory initData =
            abi.encodeWithSelector(BasePaintMarket.initialize.selector, address(basePaint), address(weth), marketOwner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        market = BasePaintMarket(payable(address(proxy)));

        // F6 (2026-06-19): run the v1.13 reinitializer so the contract is in its
        // real post-upgrade state (mini-set floor set) while the fuzzer exercises
        // the 24 mini types. reinitializer(2) — runs exactly once.
        market.initializeV13(0.1 ether);

        handler = new MarketHandler(market, basePaint, weth);

        // Restrict fuzzer's targeting surface to handler-mediated calls.
        // Without this, Foundry would call market/basePaint/weth directly and
        // immediately wreck setUp invariants.
        targetContract(address(handler));

        // Whitelist only the action functions we want sequenced.
        // Note: omit handler.acceptedDigestsLength (a view) — invariant runner
        // already skips view functions, but explicit selectors avoid surprise.
        bytes4[] memory selectors = new bytes4[](9);
        selectors[0] = handler.createListing.selector;
        selectors[1] = handler.cancelListing.selector;
        selectors[2] = handler.buyListing.selector;
        selectors[3] = handler.acceptCollectionOffer.selector;
        selectors[4] = handler.cancelAllOffers.selector;
        // Admin actions (audit 2026-07-24 §1.4): invariants I1–I6 must hold
        // under pause/unpause, fee changes, and blacklist churn too.
        selectors[5] = handler.adminPause.selector;
        selectors[6] = handler.adminUnpause.selector;
        selectors[7] = handler.adminSetPlatformFee.selector;
        selectors[8] = handler.adminSetBlacklist.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// I1: ETH balance must always cover accumulated ETH fees.
    /// If false, an owner withdrawal would fail or worse, fees would be diluted by
    /// some other payment path that doesn't credit platformFeesAccumulated.
    function invariant_ethSolvency() public view {
        assertGe(address(market).balance, market.platformFeesAccumulated(), "I1: ETH solvency");
    }

    /// I2: WETH balance must always cover accumulated WETH fees.
    function invariant_wethSolvency() public view {
        assertGe(weth.balanceOf(address(market)), market.platformFeesAccumulatedWETH(), "I2: WETH solvency");
    }

    /// I3: Fee is hard-capped at MAX_PLATFORM_FEE (1000 bps = 10%).
    /// The handler's adminSetPlatformFee action exercises the setter across the
    /// full legal range; this assertion catches both an over-cap set and any
    /// unexpected fee mutation by a non-admin path.
    function invariant_feeBounded() public view {
        assertLe(market.platformFee(), market.MAX_PLATFORM_FEE(), "I3: fee bound");
    }

    /// I4: activeListingByUser points to a listing that is .active OR is the sentinel 0.
    /// A non-zero pointer to an inactive listing means a state-machine bug:
    /// cancel/buy/expire didn't clear the index.
    function invariant_activeListingPointerConsistent() public view {
        address[3] memory ss = [handler.sellers(0), handler.sellers(1), handler.sellers(2)];
        for (uint256 i = 0; i < ss.length; i++) {
            // F6 (2026-06-19): iterate ALL 26 bundle types, not just the 2 years.
            // The dangling-pointer bug class (H-01) is exactly what the year<->mini
            // overlap could reintroduce, so every mini pointer must be checked too.
            for (uint256 j = 0; j < 26; j++) {
                uint256 listingId = market.activeListingByUser(ss[i], BasePaintMarket.BundleType(j));
                if (listingId == 0) continue;
                (,,,, bool active,) = market.listings(listingId);
                assertTrue(active, "I4: activeListingByUser points to inactive listing");
            }
        }
    }

    /// I5: market never holds BasePaint NFTs.
    /// The protocol is approval-based — NFTs go seller → buyer directly via
    /// safeBatchTransferFrom. Any non-zero balance means a flow accidentally
    /// transferred into the market (e.g. legacy escrow code reintroduced).
    /// We check the boundary tokens (1, 365, 366, 730) plus a few interior
    /// IDs — full-range loop of 730 tokens × every fuzz step would dominate runtime.
    function invariant_noNftCustody() public view {
        address m = address(market);
        assertEq(basePaint.balanceOf(m, 1), 0, "I5: market holds tokenId 1");
        assertEq(basePaint.balanceOf(m, 30), 0, "I5: market holds tokenId 30"); // MINI_1 end (F6)
        assertEq(basePaint.balanceOf(m, 100), 0, "I5: market holds tokenId 100");
        assertEq(basePaint.balanceOf(m, 365), 0, "I5: market holds tokenId 365");
        assertEq(basePaint.balanceOf(m, 366), 0, "I5: market holds tokenId 366");
        assertEq(basePaint.balanceOf(m, 500), 0, "I5: market holds tokenId 500");
        assertEq(basePaint.balanceOf(m, 696), 0, "I5: market holds tokenId 696"); // MINI_24 start (F6)
        assertEq(basePaint.balanceOf(m, 730), 0, "I5: market holds tokenId 730");
    }

    /// I6: every digest ever flipped to usedSignatures=true stays true.
    /// Replay-protection regression — usedSignatures should be append-only.
    /// Handler tracks every successful acceptCollectionOffer's digest in acceptedDigests.
    function invariant_signaturesNeverUnused() public view {
        uint256 n = handler.acceptedDigestsLength();
        for (uint256 i = 0; i < n; i++) {
            assertTrue(market.isSignatureUsed(handler.acceptedDigests(i)), "I6: replay protection regression");
        }
    }

    // NOTE on action reachability:
    // Foundry runs invariant checks BOTH before and after the fuzz sequence,
    // so a `callCount > 0` sanity check fails at setup-time (the empty initial
    // state). The trace summary printed at the end of `forge test` is the right
    // place to verify the fuzzer actually exercised every handler function —
    // each action shows its call count and we expect non-zero. As of the
    // 2026-07-24 admin-action close-out: ~14k calls per action
    // (256 runs × 500 depth distributed across 9 actions, admin actions
    // included) — verified over 3+ consecutive green runs.
}
