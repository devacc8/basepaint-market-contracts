// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BasePaintMarket} from "../../src/BasePaintMarket.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {MockERC1271Wallet} from "../mocks/MockERC1271Wallet.sol";

/// Minimal canonical-WETH surface used to fund an offer buyer on the fork.
interface IWETH {
    function deposit() external payable;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title UpgradeForkSim
 * @notice Dynamic dress-rehearsal of the v1.13 -> v1.14 mainnet upgrade against a
 *         FORK of the LIVE Base mainnet proxy state. Nothing touches mainnet — anvil
 *         clones the real proxy storage locally and every write happens only on the
 *         local fork; the RPC is used purely to READ state.
 *
 * v1.14 is an EMPTY-CALLDATA upgrade (pure logic: self-trade guard + getActiveListings
 * `>=` expiry boundary; NO new storage, NO reinitializer) — exactly what
 * script/UpgradeMarket.s.sol broadcasts.
 *
 * `setUp` runs the exact upgrade ONCE against the forked live proxy; Foundry snapshots
 * that post-upgrade state and reverts to it before each test, so every scenario below
 * starts from the same real state with the complete-set HOLDER's balances intact (no
 * cross-test overlap between the year sale and the mini/offer sales).
 *
 * Run (only meaningful on a fork; auto-skips in the normal unit suite):
 *   forge test --match-path test/fork/UpgradeForkSim.t.sol --fork-url base -vvv
 */
contract UpgradeForkSim is Test {
    // Live Base mainnet
    BasePaintMarket constant PROXY = BasePaintMarket(payable(0xB0897037052BB9104CcDF743358ea4f91990A362));
    address constant OWNER = 0xb622728b75010df13073FC6d0B2D6A450d98dFCc;
    IERC1155 constant BASEPAINT = IERC1155(0xBa5e05cb26b78eDa3A2f8e3b3814726305dcAc83);

    // Real year-1 complete-set holder (owns days 1-365), sourced from the prod
    // dashboard cache — enough for a full-year sale AND any mini sale in isolation.
    address constant HOLDER = 0x0a5F07eCa94861D5804891cB9078171BBb0fd046;

    // Pre-upgrade snapshots (captured in setUp before the swap; asserted preserved).
    bool internal forked;
    address internal preOwner;
    uint256 internal preNextId;
    uint256 internal prePlatformFee;
    uint256 internal preFeesEth;
    uint256 internal preMinListingPrice;
    uint256 internal preMiniFloor;
    address internal preBasePaint;
    address internal preWeth;

    function setUp() public {
        // Off-fork (normal unit suite): the live proxy has no code here — do nothing
        // and let every test skip via the onlyFork modifier.
        if (block.chainid != 8453) return;
        forked = true;

        preOwner = PROXY.owner();
        preNextId = PROXY.nextListingId();
        prePlatformFee = PROXY.platformFee();
        preFeesEth = PROXY.platformFeesAccumulated();
        preMinListingPrice = PROXY.minListingPrice();
        preMiniFloor = PROXY.minMiniListingPrice();
        preBasePaint = address(PROXY.basePaint());
        preWeth = address(PROXY.weth());

        // v1.14: plain implementation swap, EMPTY call data (no reinitializer).
        // initializeV13's reinitializer(2) is already consumed on the live proxy;
        // re-calling it would revert. Mirrors script/UpgradeMarket.s.sol exactly.
        BasePaintMarket newImpl = new BasePaintMarket();
        vm.prank(OWNER);
        PROXY.upgradeToAndCall(address(newImpl), "");
    }

    modifier onlyFork() {
        if (!forked) {
            vm.skip(true);
            return;
        }
        _;
    }

    // ---- upgrade safety ----------------------------------------------------

    /// Every v1.13 storage slot survives the pure-logic v1.14 swap.
    function test_UpgradePreservesLiveState() public onlyFork {
        assertGt(preMiniFloor, 0, "expected v1.13 mini floor already set");
        assertEq(PROXY.owner(), preOwner, "owner changed");
        assertEq(PROXY.nextListingId(), preNextId, "nextListingId changed");
        assertEq(PROXY.platformFee(), prePlatformFee, "platformFee changed");
        assertEq(PROXY.minListingPrice(), preMinListingPrice, "minListingPrice changed");
        assertEq(PROXY.minMiniListingPrice(), preMiniFloor, "minMiniListingPrice changed");
        assertEq(address(PROXY.basePaint()), preBasePaint, "basePaint changed");
        assertEq(address(PROXY.weth()), preWeth, "weth changed");
        assertEq(PROXY.platformFeesAccumulated(), preFeesEth, "feesEth changed");
    }

    /// v1.13 range views still resolve correctly on the upgraded proxy.
    function test_RangeViewsResolve() public onlyFork {
        (uint256 s1, uint256 e1) = PROXY.getBundleDayRange(BasePaintMarket.BundleType.YEAR_1);
        assertEq(s1, 1, "y1 start");
        assertEq(e1, 365, "y1 end");
        (uint256 sm12, uint256 em12) = PROXY.getBundleDayRange(BasePaintMarket.BundleType.MINI_12);
        assertEq(sm12, 331, "m12 start");
        assertEq(em12, 365, "m12 end (35d closing)");
        (uint256 sm24, uint256 em24) = PROXY.getBundleDayRange(BasePaintMarket.BundleType.MINI_24);
        assertEq(sm24, 696, "m24 start");
        assertEq(em24, 730, "m24 end (35d closing)");
    }

    /// v1.14 self-trade guard is live: the seller cannot buy their own listing.
    function test_SelfTradeGuardLive() public onlyFork {
        uint256 listingId = _holderList(BasePaintMarket.BundleType.MINI_1, 0.5 ether);
        vm.deal(HOLDER, 1 ether);
        vm.prank(HOLDER);
        vm.expectRevert(BasePaintMarket.SelfTrade.selector);
        PROXY.buyListing{value: 0.5 ether}(listingId);
    }

    // ---- real trades end-to-end on the upgraded proxy ----------------------

    /// A real holder lists mini-1 and a different funded buyer purchases it.
    function test_MiniPurchaseSettles() public onlyFork {
        _assertHolderOwnsRange(1, 30);
        uint256 listingId = _holderList(BasePaintMarket.BundleType.MINI_1, 0.5 ether);

        address buyer = makeAddr("miniBuyer");
        vm.deal(buyer, 1 ether);
        uint256 sellerEthBefore = HOLDER.balance;
        uint256 sellerDay1Before = BASEPAINT.balanceOf(HOLDER, 1);
        uint256 sellerDay30Before = BASEPAINT.balanceOf(HOLDER, 30);

        vm.prank(buyer);
        PROXY.buyListing{value: 0.5 ether}(listingId);

        // Buyer receives exactly one of each day; the seller (who may hold extra
        // copies) is decremented by exactly one — the bundle moves one complete set.
        assertEq(BASEPAINT.balanceOf(buyer, 1), 1, "buyer missing day 1");
        assertEq(BASEPAINT.balanceOf(buyer, 30), 1, "buyer missing day 30");
        assertEq(BASEPAINT.balanceOf(HOLDER, 1), sellerDay1Before - 1, "seller day 1 not decremented by 1");
        assertEq(BASEPAINT.balanceOf(HOLDER, 30), sellerDay30Before - 1, "seller day 30 not decremented by 1");
        _assertSellerEthPayout(sellerEthBefore, 0.5 ether);
    }

    /// The full year-1 set (365 NFTs) lists and settles in a single buyListing tx.
    function test_YearPurchaseSettles() public onlyFork {
        _assertHolderOwnsRange(1, 365);
        // Years use the 1 ETH floor; 5 ETH clears it.
        uint256 listingId = _holderList(BasePaintMarket.BundleType.YEAR_1, 5 ether);

        address buyer = makeAddr("yearBuyer");
        vm.deal(buyer, 6 ether);
        uint256 sellerEthBefore = HOLDER.balance;
        uint256 sellerDay1Before = BASEPAINT.balanceOf(HOLDER, 1);
        uint256 sellerDay200Before = BASEPAINT.balanceOf(HOLDER, 200);
        uint256 sellerDay365Before = BASEPAINT.balanceOf(HOLDER, 365);

        vm.prank(buyer);
        PROXY.buyListing{value: 5 ether}(listingId);

        // Buyer receives one of each day across the full 365-day range; the seller
        // (who holds extra copies of some days — real accumulated state) is
        // decremented by exactly one each. The bundle moves one complete set.
        assertEq(BASEPAINT.balanceOf(buyer, 1), 1, "buyer missing day 1");
        assertEq(BASEPAINT.balanceOf(buyer, 200), 1, "buyer missing day 200");
        assertEq(BASEPAINT.balanceOf(buyer, 365), 1, "buyer missing day 365");
        assertEq(BASEPAINT.balanceOf(HOLDER, 1), sellerDay1Before - 1, "seller day 1 not decremented by 1");
        assertEq(BASEPAINT.balanceOf(HOLDER, 200), sellerDay200Before - 1, "seller day 200 not decremented by 1");
        assertEq(BASEPAINT.balanceOf(HOLDER, 365), sellerDay365Before - 1, "seller day 365 not decremented by 1");
        _assertSellerEthPayout(sellerEthBefore, 5 ether);
    }

    /// A WETH-funded buyer signs an EIP-712 collection offer for mini-1 and the
    /// holder accepts it — the off-chain-signature path settles on the upgraded proxy.
    function test_CollectionOfferAcceptance() public onlyFork {
        _assertHolderOwnsRange(1, 30);

        (address offerBuyer, uint256 offerBuyerPk) = makeAddrAndKey("offerBuyer");
        uint256 price = 0.4 ether;
        address wethAddr = address(PROXY.weth());

        // Fund the buyer with REAL WETH (wrap ETH) and approve the market to spend it.
        vm.deal(offerBuyer, price);
        vm.startPrank(offerBuyer);
        IWETH(wethAddr).deposit{value: price}();
        IWETH(wethAddr).approve(address(PROXY), price);
        vm.stopPrank();

        // Seller approves the market for the NFTs.
        vm.prank(HOLDER);
        BASEPAINT.setApprovalForAll(address(PROXY), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: offerBuyer,
            bundleType: BasePaintMarket.BundleType.MINI_1,
            price: price,
            expiresAt: block.timestamp + 7 days,
            salt: 0xF0FA,
            nonce: PROXY.offerNonces(offerBuyer)
        });
        bytes memory sig = _signOffer(offer, offerBuyerPk);

        uint256 sellerWethBefore = IWETH(wethAddr).balanceOf(HOLDER);
        uint256 sellerDay1Before = BASEPAINT.balanceOf(HOLDER, 1);
        uint256 sellerDay30Before = BASEPAINT.balanceOf(HOLDER, 30);

        vm.prank(HOLDER);
        PROXY.acceptCollectionOffer(offer, sig);

        // Buyer received one of each mini-1 day; seller decremented by one and got
        // WETH = price - 2% fee.
        assertEq(BASEPAINT.balanceOf(offerBuyer, 1), 1, "buyer missing day 1");
        assertEq(BASEPAINT.balanceOf(offerBuyer, 30), 1, "buyer missing day 30");
        assertEq(BASEPAINT.balanceOf(HOLDER, 1), sellerDay1Before - 1, "seller day 1 not decremented by 1");
        assertEq(BASEPAINT.balanceOf(HOLDER, 30), sellerDay30Before - 1, "seller day 30 not decremented by 1");

        uint256 expectedFee = (price * prePlatformFee) / 10000;
        assertEq(IWETH(wethAddr).balanceOf(HOLDER), sellerWethBefore + price - expectedFee, "seller WETH payout wrong");
    }

    /// v1.14 (audit L-1): a smart-contract wallet (EIP-1271) buyer's collection
    /// offer is accepted on the upgraded proxy — exercised against the REAL WETH
    /// and BasePaint contracts. The wallet is controlled by an owner EOA that
    /// signs the EIP-712 offer; SignatureChecker routes the contract account to
    /// isValidSignature. This is the path that was silently impossible pre-v1.14.
    function test_CollectionOfferAcceptance_SmartWallet1271() public onlyFork {
        _assertHolderOwnsRange(1, 30);

        (address walletOwner, uint256 walletOwnerPk) = makeAddrAndKey("smartWalletOwner");
        MockERC1271Wallet wallet = new MockERC1271Wallet(walletOwner);
        uint256 price = 0.4 ether;
        address wethAddr = address(PROXY.weth());

        // Fund the WALLET (the buyer of record) with real WETH and approve the market.
        vm.deal(address(wallet), price);
        vm.startPrank(address(wallet));
        IWETH(wethAddr).deposit{value: price}();
        IWETH(wethAddr).approve(address(PROXY), price);
        vm.stopPrank();

        vm.prank(HOLDER);
        BASEPAINT.setApprovalForAll(address(PROXY), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: address(wallet),
            bundleType: BasePaintMarket.BundleType.MINI_1,
            price: price,
            expiresAt: block.timestamp + 7 days,
            salt: 0x1271,
            nonce: PROXY.offerNonces(address(wallet))
        });
        // Signed by the wallet's OWNER key; the wallet validates it via isValidSignature.
        bytes memory sig = _signOffer(offer, walletOwnerPk);

        uint256 sellerWethBefore = IWETH(wethAddr).balanceOf(HOLDER);
        uint256 sellerDay1Before = BASEPAINT.balanceOf(HOLDER, 1);
        uint256 sellerDay30Before = BASEPAINT.balanceOf(HOLDER, 30);

        vm.prank(HOLDER);
        PROXY.acceptCollectionOffer(offer, sig);

        // The smart wallet received the bundle (proving it accepted the ERC1155
        // batch too); seller decremented by one and paid in WETH minus 2% fee.
        assertEq(BASEPAINT.balanceOf(address(wallet), 1), 1, "smart wallet missing day 1");
        assertEq(BASEPAINT.balanceOf(address(wallet), 30), 1, "smart wallet missing day 30");
        assertEq(BASEPAINT.balanceOf(HOLDER, 1), sellerDay1Before - 1, "seller day 1 not decremented by 1");
        assertEq(BASEPAINT.balanceOf(HOLDER, 30), sellerDay30Before - 1, "seller day 30 not decremented by 1");
        uint256 expectedFee = (price * prePlatformFee) / 10000;
        assertEq(IWETH(wethAddr).balanceOf(HOLDER), sellerWethBefore + price - expectedFee, "seller WETH payout wrong");
    }

    /// v1.14 (audit L-1): a 1271 wallet whose owner did NOT sign is rejected
    /// on-chain — isValidSignature returns a non-magic value, so
    /// acceptCollectionOffer reverts InvalidSignature (no NFT/WETH movement).
    function test_SmartWallet1271_WrongSigner_Rejected() public onlyFork {
        (, uint256 strangerPk) = makeAddrAndKey("stranger");
        MockERC1271Wallet wallet = new MockERC1271Wallet(makeAddr("realOwner")); // owner != stranger
        uint256 price = 0.4 ether;
        address wethAddr = address(PROXY.weth());

        vm.deal(address(wallet), price);
        vm.startPrank(address(wallet));
        IWETH(wethAddr).deposit{value: price}();
        IWETH(wethAddr).approve(address(PROXY), price);
        vm.stopPrank();

        vm.prank(HOLDER);
        BASEPAINT.setApprovalForAll(address(PROXY), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: address(wallet),
            bundleType: BasePaintMarket.BundleType.MINI_1,
            price: price,
            expiresAt: block.timestamp + 7 days,
            salt: 0x1272,
            nonce: PROXY.offerNonces(address(wallet))
        });
        // Signed by a stranger, not the wallet's owner → 1271 returns non-magic.
        bytes memory sig = _signOffer(offer, strangerPk);

        vm.prank(HOLDER);
        vm.expectRevert(BasePaintMarket.InvalidSignature.selector);
        PROXY.acceptCollectionOffer(offer, sig);
    }

    /// v1.14 (L-1) at scale: a smart-contract wallet accepts a FULL year-1 offer
    /// (365 NFTs) — confirms a contract buyer can receive the large ERC1155 batch
    /// via onERC1155BatchReceived on real state.
    function test_YearOfferAcceptance_SmartWallet1271() public onlyFork {
        _assertHolderOwnsRange(1, 365);

        (address walletOwner, uint256 walletOwnerPk) = makeAddrAndKey("yearWalletOwner");
        MockERC1271Wallet wallet = new MockERC1271Wallet(walletOwner);
        uint256 price = 5 ether; // clears the 1 ETH year floor
        address wethAddr = address(PROXY.weth());

        vm.deal(address(wallet), price);
        vm.startPrank(address(wallet));
        IWETH(wethAddr).deposit{value: price}();
        IWETH(wethAddr).approve(address(PROXY), price);
        vm.stopPrank();

        vm.prank(HOLDER);
        BASEPAINT.setApprovalForAll(address(PROXY), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: address(wallet),
            bundleType: BasePaintMarket.BundleType.YEAR_1,
            price: price,
            expiresAt: block.timestamp + 7 days,
            salt: 0x1273,
            nonce: PROXY.offerNonces(address(wallet))
        });
        bytes memory sig = _signOffer(offer, walletOwnerPk);

        uint256 sellerWethBefore = IWETH(wethAddr).balanceOf(HOLDER);
        uint256 sellerDay1Before = BASEPAINT.balanceOf(HOLDER, 1);
        uint256 sellerDay365Before = BASEPAINT.balanceOf(HOLDER, 365);

        vm.prank(HOLDER);
        PROXY.acceptCollectionOffer(offer, sig);

        assertEq(BASEPAINT.balanceOf(address(wallet), 1), 1, "wallet missing day 1");
        assertEq(BASEPAINT.balanceOf(address(wallet), 200), 1, "wallet missing day 200");
        assertEq(BASEPAINT.balanceOf(address(wallet), 365), 1, "wallet missing day 365");
        assertEq(BASEPAINT.balanceOf(HOLDER, 1), sellerDay1Before - 1, "seller day 1 not decremented by 1");
        assertEq(BASEPAINT.balanceOf(HOLDER, 365), sellerDay365Before - 1, "seller day 365 not decremented by 1");
        uint256 expectedFee = (price * prePlatformFee) / 10000;
        assertEq(IWETH(wethAddr).balanceOf(HOLDER), sellerWethBefore + price - expectedFee, "seller WETH payout wrong");
    }

    /// v1.14 (L-1) negative: a 1271 wallet with no WETH is rejected at the funding
    /// check (signature validates, balance does not).
    function test_SmartWallet1271_Underfunded_Rejected() public onlyFork {
        (address walletOwner, uint256 walletOwnerPk) = makeAddrAndKey("poorWalletOwner");
        MockERC1271Wallet wallet = new MockERC1271Wallet(walletOwner); // funded with 0 WETH

        vm.prank(HOLDER);
        BASEPAINT.setApprovalForAll(address(PROXY), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: address(wallet),
            bundleType: BasePaintMarket.BundleType.MINI_1,
            price: 0.4 ether,
            expiresAt: block.timestamp + 7 days,
            salt: 0x1274,
            nonce: PROXY.offerNonces(address(wallet))
        });
        bytes memory sig = _signOffer(offer, walletOwnerPk);

        vm.prank(HOLDER);
        vm.expectRevert(BasePaintMarket.InsufficientWETHBalance.selector);
        PROXY.acceptCollectionOffer(offer, sig);
    }

    /// v1.14 (L-1) negative: a 1271 offer cannot be replayed — the digest-keyed
    /// usedSignatures guard reverts the second acceptance before any re-settlement.
    function test_SmartWallet1271_ReplayRejected() public onlyFork {
        (address walletOwner, uint256 walletOwnerPk) = makeAddrAndKey("replayWalletOwner");
        MockERC1271Wallet wallet = new MockERC1271Wallet(walletOwner);
        uint256 price = 0.4 ether;
        address wethAddr = address(PROXY.weth());

        vm.deal(address(wallet), price);
        vm.startPrank(address(wallet));
        IWETH(wethAddr).deposit{value: price}();
        IWETH(wethAddr).approve(address(PROXY), price);
        vm.stopPrank();

        vm.prank(HOLDER);
        BASEPAINT.setApprovalForAll(address(PROXY), true);

        BasePaintMarket.CollectionOfferParams memory offer = BasePaintMarket.CollectionOfferParams({
            buyer: address(wallet),
            bundleType: BasePaintMarket.BundleType.MINI_1,
            price: price,
            expiresAt: block.timestamp + 7 days,
            salt: 0x1275,
            nonce: PROXY.offerNonces(address(wallet))
        });
        bytes memory sig = _signOffer(offer, walletOwnerPk);

        vm.prank(HOLDER);
        PROXY.acceptCollectionOffer(offer, sig); // first acceptance settles

        vm.prank(HOLDER);
        vm.expectRevert(BasePaintMarket.SignatureAlreadyUsed.selector);
        PROXY.acceptCollectionOffer(offer, sig); // replay rejected
    }

    /// v1.14 (MEDIUM-01) on live state: at its EXACT expiry second a listing is
    /// still returned by getActiveListings AND still buyable — "visible <=> buyable".
    function test_ExpiryBoundaryVisibleAndBuyable() public onlyFork {
        uint256 listingId = _holderList(BasePaintMarket.BundleType.MINI_1, 0.5 ether);
        uint256 expiresAt = PROXY.getListing(listingId).expiresAt;

        vm.warp(expiresAt); // the exact expiry second
        assertTrue(_activeListingsContains(listingId), "listing must be visible at its exact expiry second");

        address buyer = makeAddr("boundaryBuyer");
        vm.deal(buyer, 1 ether);
        vm.prank(buyer);
        PROXY.buyListing{value: 0.5 ether}(listingId); // still buyable in that same second
        assertEq(BASEPAINT.balanceOf(buyer, 1), 1, "purchase at the expiry second must succeed");
    }

    // ---- helpers -----------------------------------------------------------

    /// Holder approves + lists `bt`; the first new listing takes the pre-upgrade
    /// nextListingId (fresh per test thanks to the setUp snapshot).
    function _holderList(BasePaintMarket.BundleType bt, uint256 price) internal returns (uint256) {
        vm.startPrank(HOLDER);
        BASEPAINT.setApprovalForAll(address(PROXY), true);
        PROXY.createListing(bt, price, 7 days);
        vm.stopPrank();
        return preNextId;
    }

    function _assertHolderOwnsRange(uint256 startDay, uint256 endDay) internal view {
        for (uint256 day = startDay; day <= endDay; day++) {
            assertGe(BASEPAINT.balanceOf(HOLDER, day), 1, "holder missing a day (stale cache?)");
        }
    }

    /// Page through getActiveListings (the live market may hold other listings)
    /// and report whether `listingId` appears anywhere in the active set.
    function _activeListingsContains(uint256 listingId) internal view returns (bool) {
        for (uint256 offset = 0;; offset += 100) {
            (uint256[] memory ids,, uint256 total) = PROXY.getActiveListings(offset, 100);
            for (uint256 i = 0; i < ids.length; i++) {
                if (ids[i] == listingId) return true;
            }
            if (offset + 100 >= total) return false;
        }
    }

    function _assertSellerEthPayout(uint256 sellerEthBefore, uint256 price) internal view {
        uint256 expectedFee = (price * prePlatformFee) / 10000;
        assertEq(HOLDER.balance, sellerEthBefore + price - expectedFee, "seller ETH payout wrong");
    }

    /// Sign a collection offer with `pk` against the PROXY's EIP-712 domain.
    function _signOffer(BasePaintMarket.CollectionOfferParams memory offer, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                PROXY.COLLECTION_OFFER_TYPEHASH(),
                offer.buyer,
                offer.bundleType,
                offer.price,
                offer.expiresAt,
                offer.salt,
                offer.nonce
            )
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("BasePaintMarket"),
                keccak256("1"),
                block.chainid,
                address(PROXY)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
