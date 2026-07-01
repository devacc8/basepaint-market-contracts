// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title BasePaintMarket
 * @notice NFT marketplace for trading complete BasePaint year bundles on Base L2
 * @dev Approval-based listings with weth signature-based offers
 * @dev v1.5: Added bundle ownership validation in buyListing/acceptCollectionOffer for better UX
 * @dev v1.6: Added listing expiration (duration parameter) and cleanup functions
 * @dev v1.7: Added cancelAllOffers() for on-chain offer cancellation, emergencyMessage length limit
 * @dev v1.8: WETH transfer before NFT (fail-fast), zero address check for offer.buyer
 * @dev v1.9: Batch limit for cleanupExpiredListings
 * @dev v1.10: Seller blacklist check in buyListing
 * @dev v1.11: SafeERC20 for WETH, Ownable2Step, filter expired in getActiveListings
 * @dev v1.12: Audit 2026-05-18 SC H-01 — clear activeListingByUser in createListing auto-cleanup branch (was already cleared in cancelListing / acceptCollectionOffer / cleanupExpiredListings, missing only here)
 * @dev v1.13: Mini-set bundles (24 × 30/35-day sets via appended enum + pure
 *      range formula) + per-category min price. Ships the deferred 2026-05-18
 *      SC audit batch: M-01 (CEI: WETH payout before the NFT transfer in
 *      acceptCollectionOffer; buyListing keeps ETH-after-NFT by design — see
 *      its note), M-02 (MAX_OFFER_DURATION), L-01 (min-price bounds),
 *      L-03 (cleanup while paused), L-04 (_clearListing helper — makes H-01
 *      structural). L-02 (indefinite pause) accepted as-design (see pause()).
 * @custom:security-contact security@basepaintmarket.xyz
 */
contract BasePaintMarket is
    Initializable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable
{
    using EnumerableSet for EnumerableSet.UintSet;
    using SafeERC20 for IERC20;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice BasePaint ERC1155 NFT contract
    IERC1155 public basePaint;

    /// @notice weth token contract
    IERC20 public weth;

    /// @notice Platform fee in basis points (200 = 2%)
    uint256 public platformFee;

    /// @notice Maximum allowed platform fee (1000 = 10%)
    uint256 public constant MAX_PLATFORM_FEE = 1000;

    /// @notice Minimum listing duration (1 day)
    uint256 public constant MIN_LISTING_DURATION = 1 days;

    /// @notice Maximum listing duration (180 days)
    uint256 public constant MAX_LISTING_DURATION = 180 days;

    /// @notice Max future window an acceptable offer may expire within (v1.13, audit M-02).
    /// @dev A stale offer signed with expiresAt far in the future can never be
    ///      accepted — protects forgotten / stolen-key offers.
    uint256 public constant MAX_OFFER_DURATION = 90 days;

    /// @notice Sanity bounds for owner-set minimum listing prices (v1.13, audit L-01).
    uint256 public constant MIN_FLOOR_BOUND = 0.001 ether;
    uint256 public constant MAX_FLOOR_BOUND = 1000 ether;

    /// @notice Accumulated platform fees in ETH (from buyListing)
    uint256 public platformFeesAccumulated;

    /// @notice Accumulated platform fees in WETH (from acceptCollectionOffer)
    uint256 public platformFeesAccumulatedWETH;

    /// @notice Minimum listing price (1 ETH default)
    uint256 public minListingPrice;

    /// @notice Counter for listing IDs
    uint256 public nextListingId;

    /// @notice Emergency message displayed on frontend
    string public emergencyMessage;

    /// @notice Bundle types available for trading.
    /// @dev APPEND-ONLY INVARIANT: these are uint8 indices persisted on-chain
    ///      (listings, offers, events). Existing values are FROZEN — never
    ///      reorder or insert; new types (e.g. a future Year 3) ALWAYS append
    ///      at the end. Day ranges are derived by `_rangeForBundle` (v1.13).
    ///      Year sets cover 365 days; mini-sets cover 30 days, except the
    ///      closing mini of each year (MINI_12, MINI_24) which covers 35.
    enum BundleType {
        YEAR_1, // 0  days   1-365  (365 NFTs)
        YEAR_2, // 1  days 366-730  (365 NFTs)
        MINI_1, // 2  days   1-30
        MINI_2, // 3  days  31-60
        MINI_3, // 4  days  61-90
        MINI_4, // 5  days  91-120
        MINI_5, // 6  days 121-150
        MINI_6, // 7  days 151-180
        MINI_7, // 8  days 181-210
        MINI_8, // 9  days 211-240
        MINI_9, // 10 days 241-270
        MINI_10, // 11 days 271-300
        MINI_11, // 12 days 301-330
        MINI_12, // 13 days 331-365 (35d, closing)
        MINI_13, // 14 days 366-395
        MINI_14, // 15 days 396-425
        MINI_15, // 16 days 426-455
        MINI_16, // 17 days 456-485
        MINI_17, // 18 days 486-515
        MINI_18, // 19 days 516-545
        MINI_19, // 20 days 546-575
        MINI_20, // 21 days 576-605
        MINI_21, // 22 days 606-635
        MINI_22, // 23 days 636-665
        MINI_23, // 24 days 666-695
        MINI_24 // 25 days 696-730 (35d, closing)
    }

    /// @notice Listing structure
    /// @dev IMPORTANT: Field order must match pre-v1.6 layout for storage compatibility
    /// New fields MUST be added AFTER existing fields to preserve storage layout
    struct Listing {
        address seller;
        BundleType bundleType;
        uint256 price;
        uint256 createdAt;
        bool active;
        uint256 expiresAt; // v1.6: listing expiration timestamp (added AFTER active for storage compatibility)
    }

    /// @notice Collection offer parameters for EIP-712 signature
    /// @dev v1.7: Added nonce field for on-chain cancellation support
    struct CollectionOfferParams {
        address buyer;
        BundleType bundleType;
        uint256 price;
        uint256 expiresAt;
        uint256 salt;
        uint256 nonce; // v1.7: must match offerNonces[buyer]
    }

    /// @notice Mapping of listing ID to Listing
    mapping(uint256 => Listing) public listings;

    /// @notice Mapping to track active listing per user per bundle type (prevents duplicates)
    mapping(address => mapping(BundleType => uint256)) public activeListingByUser;

    /// @notice Mapping to track used offer signatures (prevent replay)
    mapping(bytes32 => bool) public usedSignatures;

    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklist;

    /// @notice Set of active listing IDs (v1.3 - gas optimization for getActiveListings)
    EnumerableSet.UintSet private activeListingIds;

    /// @notice Mapping of offer nonces per user (v1.7 - for on-chain offer cancellation)
    /// @dev Incrementing nonce invalidates all previous offers
    mapping(address => uint256) public offerNonces;

    /// @notice Maximum length for emergency message (v1.7)
    uint256 public constant MAX_EMERGENCY_MESSAGE_LENGTH = 500;

    /// @notice Minimum listing price for mini-set bundles (v1.13).
    /// @dev Years use `minListingPrice` (1 ETH); minis use this lower floor.
    ///      Added in the first free `__gap` slot — see the reduced gap below.
    uint256 public minMiniListingPrice;

    /// @notice Storage gap for future upgrades (v1.4)
    /// @dev Reserve 48 slots (v1.13: reduced 49→48 for minMiniListingPrice)
    uint256[48] private __gap;

    // EIP-712 typehash for collection offers
    // v1.7: Added nonce field for on-chain cancellation support
    bytes32 public constant COLLECTION_OFFER_TYPEHASH = keccak256(
        "CollectionOffer(address buyer,uint8 bundleType,uint256 price,uint256 expiresAt,uint256 salt,uint256 nonce)"
    );

    // ============================================
    // EVENTS
    // ============================================

    event ListingCreated(
        uint256 indexed listingId,
        address indexed seller,
        BundleType bundleType,
        uint256 price,
        uint256 expiresAt,
        uint256 timestamp
    );

    event ListingCancelled(uint256 indexed listingId, BundleType bundleType, uint256 timestamp);

    event ListingExpiredAndCleaned(uint256 indexed listingId, BundleType bundleType, uint256 timestamp);

    event ListingSold(
        uint256 indexed listingId,
        address indexed buyer,
        address indexed seller,
        BundleType bundleType,
        uint256 price,
        uint256 fee,
        uint256 timestamp
    );

    event CollectionOfferAccepted(
        address indexed buyer,
        address indexed seller,
        BundleType bundleType,
        uint256 price,
        uint256 fee,
        uint256 timestamp,
        uint256 salt
    );

    event PlatformFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinListingPriceUpdated(uint256 oldPrice, uint256 newPrice);
    event MinMiniListingPriceUpdated(uint256 oldPrice, uint256 newPrice); // v1.13
    event PlatformFeesWithdrawn(address indexed recipient, uint256 amount);
    event PlatformFeesWithdrawnWETH(address indexed recipient, uint256 amount);
    event BlacklistUpdated(address indexed user, bool blacklisted);
    event EmergencyMessageSet(string message);
    event ContractPaused(string reason);
    event ContractUnpaused();
    event AllOffersCancelled(address indexed user, uint256 newNonce);

    // ============================================
    // ERRORS
    // ============================================

    error InvalidBundleType();
    error PriceTooLow();
    error NotSeller();
    error ListingNotActive();
    error InsufficientPayment();
    error MissingToken(uint256 tokenId);
    error NotApproved();
    error TransferFailed();
    error InvalidSignature();
    error SignatureAlreadyUsed();
    error OfferExpired();
    error OfferTooLow();
    error InsufficientWETHBalance();
    error InsufficientWETHAllowance();
    error FeeTooHigh();
    error Blacklisted();
    error InvalidDuration();
    error DuplicateListing();
    error SelfTrade(); // v1.14 (audit LOW#1): buyer and seller must differ (no wash-trade)
    error ListingExpired();
    error ListingNotExpired();
    error NothingToWithdraw();
    error InvalidAmount();
    error OfferNonceMismatch();
    error EmergencyMessageTooLong();
    error OfferTooLong(); // v1.13 (M-02): offer expiry too far in the future
    error InvalidMinPrice(); // v1.13 (L-01): min-price setter out of sane bounds

    // ============================================
    // MODIFIERS
    // ============================================

    modifier notBlacklisted() {
        if (blacklist[msg.sender]) revert Blacklisted();
        _;
    }

    // ============================================
    // INITIALIZATION
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param _basePaint Address of BasePaint ERC1155 contract
     * @param _weth Address of weth token contract
     * @param _initialOwner Address of initial owner
     */
    function initialize(address _basePaint, address _weth, address _initialOwner) external initializer {
        require(_basePaint != address(0), "BasePaint address cannot be zero");
        require(_weth != address(0), "WETH address cannot be zero");
        require(_initialOwner != address(0), "Owner address cannot be zero");

        __ReentrancyGuard_init();
        __Pausable_init();
        __Ownable_init(_initialOwner);
        __UUPSUpgradeable_init();
        __EIP712_init("BasePaintMarket", "1");

        basePaint = IERC1155(_basePaint);
        weth = IERC20(_weth);
        platformFee = 200; // 2%
        minListingPrice = 1 ether;
        nextListingId = 1;
    }

    /**
     * @notice v1.13 upgrade initializer — sets the mini-set minimum price.
     * @param _minMiniListingPrice Initial mini-set floor (0.1 ether)
     * @dev reinitializer(2): the proxy used only the original `initialize`
     *      (version 1) across v1.4–v1.12; this is the first reinitializer.
     *      Bounds-checked like the runtime setter (L-01).
     */
    function initializeV13(uint256 _minMiniListingPrice) external reinitializer(2) {
        _requireSaneFloor(_minMiniListingPrice);
        minMiniListingPrice = _minMiniListingPrice;
        emit MinMiniListingPriceUpdated(0, _minMiniListingPrice);
    }

    // ============================================
    // LISTING FUNCTIONS
    // ============================================

    /**
     * @notice Create a new listing for a complete bundle
     * @param bundleType Type of bundle (YEAR_1 or YEAR_2)
     * @param price Asking price in ETH (must be >= minListingPrice)
     * @param duration Listing duration in seconds (min 1 day, max 180 days)
     */
    function createListing(BundleType bundleType, uint256 price, uint256 duration)
        external
        whenNotPaused
        notBlacklisted
    {
        // v1.13: per-category floor — years use minListingPrice, minis use the
        // lower minMiniListingPrice.
        if (price < (_isYear(bundleType) ? minListingPrice : minMiniListingPrice)) revert PriceTooLow();
        if (duration < MIN_LISTING_DURATION || duration > MAX_LISTING_DURATION) revert InvalidDuration();

        // Check for existing listing and auto-cleanup if expired (v1.6)
        uint256 existingListingId = activeListingByUser[msg.sender][bundleType];
        if (existingListingId != 0) {
            Listing storage existing = listings[existingListingId];
            if (existing.active) {
                // If expired - auto cleanup
                if (block.timestamp > existing.expiresAt) {
                    // v1.13 (L-04): single helper clears all three pieces —
                    // makes the H-01 invariant structural, not per-call-site.
                    _clearListing(existingListingId, existing);
                    emit ListingExpiredAndCleaned(existingListingId, bundleType, block.timestamp);
                } else {
                    // Not expired - truly active listing exists
                    revert DuplicateListing();
                }
            }
        }

        // Validate seller owns complete bundle
        _validateBundleOwnership(msg.sender, bundleType);

        // Validate seller has approved marketplace
        if (!basePaint.isApprovedForAll(msg.sender, address(this))) {
            revert NotApproved();
        }

        uint256 listingId = nextListingId++;

        listings[listingId] = Listing({
            seller: msg.sender,
            bundleType: bundleType,
            price: price,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + duration,
            active: true
        });

        // Track active listing
        activeListingByUser[msg.sender][bundleType] = listingId;

        // Add to active listings set (v1.3)
        activeListingIds.add(listingId);

        emit ListingCreated(listingId, msg.sender, bundleType, price, block.timestamp + duration, block.timestamp);
    }

    /**
     * @notice Cancel an active listing
     * @param listingId ID of the listing to cancel
     * @dev Intentionally no notBlacklisted modifier - allows blacklisted users to cleanup their listings
     */
    function cancelListing(uint256 listingId) external {
        Listing storage listing = listings[listingId];

        if (listing.seller != msg.sender) revert NotSeller();
        if (!listing.active) revert ListingNotActive();

        _clearListing(listingId, listing); // v1.13 (L-04)

        emit ListingCancelled(listingId, listing.bundleType, block.timestamp);
    }

    /**
     * @notice Buy a listing at fixed price
     * @param listingId ID of the listing to purchase
     */
    function buyListing(uint256 listingId) external payable nonReentrant whenNotPaused notBlacklisted {
        Listing storage listing = listings[listingId];

        if (!listing.active) revert ListingNotActive();
        // v1.14 (LOW#1): a seller buying their own listing is a pure wash-trade
        // (pays themselves minus fee, inflates volume/last-price stats). Block it.
        if (msg.sender == listing.seller) revert SelfTrade();
        if (block.timestamp > listing.expiresAt) revert ListingExpired();
        if (msg.value < listing.price) revert InsufficientPayment();

        // Prevent trading with blacklisted sellers
        if (blacklist[listing.seller]) revert Blacklisted();

        // Validate approval still active (before expensive validation)
        if (!basePaint.isApprovedForAll(listing.seller, address(this))) {
            revert NotApproved();
        }

        // Validate bundle ownership (v1.5: fail fast with MissingToken error before state changes)
        _validateBundleOwnership(listing.seller, listing.bundleType);

        // v1.13 (L-04): single helper clears all three listing-state pieces.
        _clearListing(listingId, listing);

        // CRITICAL: Validate bundle integrity AND transfer in single call
        // Gas optimization: generates tokenIds array only ONCE.
        //
        // NOTE (v1.13): unlike acceptCollectionOffer (M-01 reorder), buyListing
        // INTENTIONALLY pays the seller AFTER the NFT transfer. Payment here is
        // native ETH via `seller.call` (a seller callback); doing it before the
        // transfer would let a contract-seller's receive() move a bundle NFT and
        // self-DoS the sale. ETH-after-NFT is the audit-correct order — the
        // asymmetry with the WETH path is deliberate. nonReentrant guards both.
        _validateAndTransferBundle(listing.seller, msg.sender, listing.bundleType);

        // Distribute payment (ETH → seller). Must stay AFTER the NFT transfer.
        _distributeFunds(listing.seller, listing.price);

        emit ListingSold(
            listingId,
            msg.sender,
            listing.seller,
            listing.bundleType,
            listing.price,
            (listing.price * platformFee) / 10000,
            block.timestamp
        );

        // Refund excess payment if any
        if (msg.value > listing.price) {
            (bool success,) = msg.sender.call{value: msg.value - listing.price}("");
            if (!success) revert TransferFailed();
        }
    }

    // ============================================
    // COLLECTION OFFER FUNCTIONS
    // ============================================

    /**
     * @notice Accept a collection offer
     * @param offer Collection offer parameters
     * @param signature EIP-712 signature from buyer
     * @dev Any holder of a complete bundle can accept a collection offer
     */
    function acceptCollectionOffer(CollectionOfferParams calldata offer, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        notBlacklisted
    {
        // Validate buyer address is not zero
        if (offer.buyer == address(0)) revert InvalidSignature();

        // v1.14 (LOW#1): the accepting seller cannot also be the offer's buyer —
        // that would be a self-trade (own bundle to self, pays self minus fee).
        if (msg.sender == offer.buyer) revert SelfTrade();

        // Prevent trading with blacklisted buyers
        if (blacklist[offer.buyer]) revert Blacklisted();

        // Validate expiration
        if (block.timestamp > offer.expiresAt) revert OfferExpired();

        // v1.13 (M-02): reject offers expiring too far in the future. A stale /
        // forgotten / stolen-key offer signed with a huge expiresAt can never be
        // accepted; legit offers (expiry within MAX_OFFER_DURATION) are fine.
        if (offer.expiresAt > block.timestamp + MAX_OFFER_DURATION) revert OfferTooLong();

        // v1.7: Validate offer nonce matches current user nonce
        if (offer.nonce != offerNonces[offer.buyer]) revert OfferNonceMismatch();

        // No minimum price check - seller explicitly accepts in UI

        // Verify EIP-712 signature (v1.7: includes nonce)
        bytes32 structHash = keccak256(
            abi.encode(
                COLLECTION_OFFER_TYPEHASH,
                offer.buyer,
                offer.bundleType,
                offer.price,
                offer.expiresAt,
                offer.salt,
                offer.nonce
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);

        if (usedSignatures[digest]) revert SignatureAlreadyUsed();

        address signer = ECDSA.recover(digest, signature);
        if (signer != offer.buyer) revert InvalidSignature();

        // Mark signature as used
        usedSignatures[digest] = true;

        // Validate WETH balance and allowance
        if (weth.balanceOf(offer.buyer) < offer.price) {
            revert InsufficientWETHBalance();
        }
        if (weth.allowance(offer.buyer, address(this)) < offer.price) {
            revert InsufficientWETHAllowance();
        }

        // Validate approval (before expensive validation)
        if (!basePaint.isApprovedForAll(msg.sender, address(this))) {
            revert NotApproved();
        }

        // Validate bundle ownership (v1.5: fail fast with MissingToken error before state changes)
        _validateBundleOwnership(msg.sender, offer.bundleType);

        // Cancel any active listing from seller for this bundle type (L-04 helper)
        uint256 existingListingId = activeListingByUser[msg.sender][offer.bundleType];
        if (existingListingId != 0 && listings[existingListingId].active) {
            _clearListing(existingListingId, listings[existingListingId]);
            emit ListingCancelled(existingListingId, offer.bundleType, block.timestamp);
        }

        // Calculate fee and seller amount
        uint256 fee = (offer.price * platformFee) / 10000;
        uint256 sellerAmount = offer.price - fee;

        // v1.13 (M-01): perform ALL WETH movements + fee accounting BEFORE the
        // NFT transfer, so the buyer's onERC1155BatchReceived callback observes a
        // fully-settled state (seller paid, fees booked). WETH transfers have no
        // seller callback, so paying first is safe here (unlike buyListing's ETH).
        weth.safeTransferFrom(offer.buyer, address(this), offer.price); // WETH in (fail-fast)
        platformFeesAccumulatedWETH += fee; // book platform fee
        weth.safeTransfer(msg.sender, sellerAmount); // pay seller

        // NFT transfer LAST — the only remaining external interaction. Reverts
        // (ERC1155InsufficientBalance) if the seller no longer holds a token,
        // unwinding the WETH moves atomically.
        _validateAndTransferBundle(msg.sender, offer.buyer, offer.bundleType);

        emit CollectionOfferAccepted(
            offer.buyer, msg.sender, offer.bundleType, offer.price, fee, block.timestamp, offer.salt
        );
    }

    // ============================================
    // OFFER CANCELLATION (v1.7)
    // ============================================

    /**
     * @notice Cancel all pending offers by incrementing nonce
     * @dev This invalidates ALL offers signed with the previous nonce
     *      Use this for emergency cancellation when backend is unavailable
     * @dev Intentionally no whenNotPaused - users must be able to cancel offers during emergencies
     */
    function cancelAllOffers() external {
        uint256 newNonce = ++offerNonces[msg.sender];
        emit AllOffersCancelled(msg.sender, newNonce);
    }

    // ============================================
    // CLEANUP FUNCTIONS (v1.6)
    // ============================================

    /**
     * @notice Clean up a single expired listing
     * @param listingId ID of the expired listing to clean up
     * @dev Anyone can call this - helps keep EnumerableSet clean
     * @dev Intentionally permissionless - ecosystem cleanup benefits all participants
     * @dev v1.13 (L-03): no `whenNotPaused` — cleanup must work during a pause
     *      so the active-set doesn't bloat with expired listings while paused.
     */
    function cleanupExpiredListing(uint256 listingId) external {
        Listing storage listing = listings[listingId];
        if (!listing.active) revert ListingNotActive();
        if (block.timestamp <= listing.expiresAt) revert ListingNotExpired();

        _clearListing(listingId, listing); // v1.13 (L-04)

        emit ListingExpiredAndCleaned(listingId, listing.bundleType, block.timestamp);
    }

    /// @notice Maximum batch size for cleanupExpiredListings (v1.9)
    uint256 public constant MAX_CLEANUP_BATCH = 100;

    /**
     * @notice Clean up multiple expired listings in one transaction
     * @param listingIds Array of listing IDs to clean up (max 100)
     * @dev Silently skips invalid/non-expired listings for gas efficiency
     * @dev Intentionally permissionless - ecosystem cleanup benefits all participants
     * @dev v1.13 (L-03): no `whenNotPaused` — cleanup must work during a pause.
     */
    function cleanupExpiredListings(uint256[] calldata listingIds) external {
        require(listingIds.length <= MAX_CLEANUP_BATCH, "Batch too large");
        for (uint256 i = 0; i < listingIds.length; i++) {
            Listing storage listing = listings[listingIds[i]];
            if (listing.active && block.timestamp > listing.expiresAt) {
                _clearListing(listingIds[i], listing); // v1.13 (L-04)
                emit ListingExpiredAndCleaned(listingIds[i], listing.bundleType, block.timestamp);
            }
        }
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Set platform fee
     * @param newFee New fee in basis points (max 1000 = 10%)
     */
    function setPlatformFee(uint256 newFee) external onlyOwner {
        if (newFee > MAX_PLATFORM_FEE) revert FeeTooHigh();

        uint256 oldFee = platformFee;
        platformFee = newFee;

        emit PlatformFeeUpdated(oldFee, newFee);
    }

    /**
     * @notice Set minimum listing price for YEAR bundles
     * @param newPrice New minimum price in wei (within sane bounds, L-01)
     */
    function setMinListingPrice(uint256 newPrice) external onlyOwner {
        _requireSaneFloor(newPrice); // v1.13 (L-01)
        uint256 oldPrice = minListingPrice;
        minListingPrice = newPrice;

        emit MinListingPriceUpdated(oldPrice, newPrice);
    }

    /**
     * @notice Set minimum listing price for MINI-SET bundles (v1.13)
     * @param newPrice New minimum price in wei (within sane bounds, L-01)
     */
    function setMinMiniListingPrice(uint256 newPrice) external onlyOwner {
        _requireSaneFloor(newPrice); // v1.13 (L-01)
        uint256 oldPrice = minMiniListingPrice;
        minMiniListingPrice = newPrice;

        emit MinMiniListingPriceUpdated(oldPrice, newPrice);
    }

    /**
     * @notice Withdraw accumulated platform fees in ETH
     * @param amount Amount to withdraw (0 = withdraw all)
     */
    function withdrawPlatformFees(uint256 amount) external onlyOwner nonReentrant {
        uint256 available = platformFeesAccumulated;
        if (available == 0) revert NothingToWithdraw();

        // If amount is 0, withdraw all available
        uint256 withdrawAmount = amount == 0 ? available : amount;

        if (withdrawAmount > available) revert InvalidAmount();

        platformFeesAccumulated = available - withdrawAmount;

        (bool success,) = owner().call{value: withdrawAmount}("");
        if (!success) revert TransferFailed();

        emit PlatformFeesWithdrawn(owner(), withdrawAmount);
    }

    /**
     * @notice Withdraw accumulated platform fees in WETH
     * @param amount Amount to withdraw (0 = withdraw all)
     */
    function withdrawPlatformFeesWETH(uint256 amount) external onlyOwner nonReentrant {
        uint256 available = platformFeesAccumulatedWETH;
        if (available == 0) revert NothingToWithdraw();

        // If amount is 0, withdraw all available
        uint256 withdrawAmount = amount == 0 ? available : amount;

        if (withdrawAmount > available) revert InvalidAmount();

        platformFeesAccumulatedWETH = available - withdrawAmount;

        weth.safeTransfer(owner(), withdrawAmount);

        emit PlatformFeesWithdrawnWETH(owner(), withdrawAmount);
    }

    /**
     * @notice Add address to blacklist
     * @param user Address to blacklist
     */
    function addToBlacklist(address user) external onlyOwner {
        blacklist[user] = true;
        emit BlacklistUpdated(user, true);
    }

    /**
     * @notice Remove address from blacklist
     * @param user Address to remove
     */
    function removeFromBlacklist(address user) external onlyOwner {
        blacklist[user] = false;
        emit BlacklistUpdated(user, false);
    }

    /**
     * @notice Set emergency message
     * @param message Message to display on frontend (max 500 chars)
     */
    function setEmergencyMessage(string calldata message) external onlyOwner {
        if (bytes(message).length > MAX_EMERGENCY_MESSAGE_LENGTH) revert EmergencyMessageTooLong();
        emergencyMessage = message;
        emit EmergencyMessageSet(message);
    }

    /**
     * @notice Pause the contract
     * @param reason Reason for pausing
     * @dev v1.13 (audit L-02, accepted as-design): pause has NO maximum duration
     *      by design. It is an emergency lever; an auto-unpause after a fixed
     *      window could re-expose users mid-incident (worse than the problem).
     *      The owner is the project team (Ownable2Step) and the effect is
     *      reversible. Users can always revoke their WETH allowance and BasePaint
     *      approval directly at the token contracts while paused, so funds are
     *      never custodially trapped. cleanupExpired* remain callable while paused
     *      (L-03) and cancelListing / cancelAllOffers omit `whenNotPaused`.
     */
    function pause(string calldata reason) external onlyOwner {
        _pause();
        emit ContractPaused(reason);
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyOwner {
        _unpause();
        emit ContractUnpaused();
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    /**
     * @notice Clear all listing state in one place (v1.13, audit L-04).
     * @dev Single source of truth for retiring a listing: flip `active`, drop
     *      the per-user/per-type pointer, and remove from the active set. Used by
     *      every clear path (cancel, auto-cleanup, offer-accept cancel, cleanup
     *      fns). Making it one helper turns the H-01 invariant (all three must be
     *      cleared together) from a per-call-site convention into structure.
     * @param listingId The listing id (for the set removal).
     * @param listing Storage ref to listings[listingId] (caller already loaded it).
     */
    function _clearListing(uint256 listingId, Listing storage listing) internal {
        listing.active = false;
        delete activeListingByUser[listing.seller][listing.bundleType];
        activeListingIds.remove(listingId);
    }

    /// @notice Revert if a min-price is outside the sane bounds (v1.13, L-01).
    function _requireSaneFloor(uint256 price) internal pure {
        if (price < MIN_FLOOR_BOUND || price > MAX_FLOOR_BOUND) revert InvalidMinPrice();
    }

    /// @notice True for the two full-year bundle types (v1.13).
    function _isYear(BundleType bundleType) internal pure returns (bool) {
        return bundleType == BundleType.YEAR_1 || bundleType == BundleType.YEAR_2;
    }

    /**
     * @notice Validate that address owns complete bundle
     * @dev Uses balanceOfBatch for gas optimization
     *      Instead of 365 separate balanceOf calls, makes 1 batched call
     * @param owner Address to validate
     * @param bundleType Type of bundle to validate
     */
    function _validateBundleOwnership(address owner, BundleType bundleType) internal view {
        uint256[] memory tokenIds = _getBundleTokenIds(bundleType);

        // Create owners array (same address repeated for each token)
        address[] memory owners = new address[](tokenIds.length);
        for (uint256 i = 0; i < tokenIds.length; i++) {
            owners[i] = owner;
        }

        // Single batched call instead of N separate calls
        uint256[] memory balances = basePaint.balanceOfBatch(owners, tokenIds);

        // Verify each token individually (NOT sum - prevents duplicate attack)
        for (uint256 i = 0; i < balances.length; i++) {
            if (balances[i] < 1) {
                revert MissingToken(tokenIds[i]);
            }
        }
    }

    /**
     * @notice Day range [start, end] (inclusive) for a bundle type (v1.13).
     * @param bundleType The bundle type (enum-gated → always a known value)
     * @return start First day token id in the bundle
     * @return end Last day token id in the bundle
     * @dev Pure + enum-gated, so the input domain is the 26 known values and the
     *      formula is exhaustively testable. Year sets span 365 days; mini-sets
     *      span 30 days except the 12th mini of each year (MINI_12 / MINI_24),
     *      the 35-day closing set — so 11×30 + 35 = 365 tiles each year exactly.
     */
    function _rangeForBundle(BundleType bundleType) internal pure returns (uint256 start, uint256 end) {
        uint256 idx = uint256(bundleType);
        if (idx == 0) return (1, 365); // YEAR_1
        if (idx == 1) return (366, 730); // YEAR_2
        uint256 n = idx - 1; // mini number 1..24 (MINI_1 == enum index 2)
        uint256 base = n <= 12 ? 0 : 365; // year offset
        uint256 k = (n - 1) % 12; // in-year index 0..11
        start = base + k * 30 + 1;
        end = (k == 11) ? base + 365 : base + (k + 1) * 30;
    }

    /**
     * @notice Get token IDs for bundle type
     * @param bundleType Type of bundle
     * @return tokenIds Array of token IDs in the bundle
     */
    function _getBundleTokenIds(BundleType bundleType) internal pure returns (uint256[] memory tokenIds) {
        (uint256 start, uint256 end) = _rangeForBundle(bundleType);
        uint256 count = end - start + 1;
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = start + i;
        }
    }

    /**
     * @notice Transfer complete bundle from seller to buyer (optimized)
     * @dev No pre-validation needed - safeBatchTransferFrom reverts if seller
     *      doesn't own any token (ERC1155InsufficientBalance error).
     *      Frontend validates bundle completeness before TX to provide better UX.
     * @param from Seller address
     * @param to Buyer address
     * @param bundleType Type of bundle to transfer
     */
    function _validateAndTransferBundle(address from, address to, BundleType bundleType) internal {
        uint256[] memory tokenIds = _getBundleTokenIds(bundleType);
        uint256[] memory amounts = new uint256[](tokenIds.length);

        for (uint256 i = 0; i < tokenIds.length; i++) {
            amounts[i] = 1;
        }

        // safeBatchTransferFrom will revert with ERC1155InsufficientBalance
        // if seller doesn't own any of the tokens
        basePaint.safeBatchTransferFrom(from, to, tokenIds, amounts, "");
    }

    /**
     * @notice Distribute payment between seller and platform
     * @param seller Seller address
     * @param totalPrice Total payment amount
     */
    function _distributeFunds(address seller, uint256 totalPrice) internal {
        uint256 fee = (totalPrice * platformFee) / 10000;
        uint256 sellerAmount = totalPrice - fee;

        platformFeesAccumulated += fee;

        (bool success,) = seller.call{value: sellerAmount}("");
        if (!success) revert TransferFailed();
    }

    /**
     * @notice Authorize contract upgrade (UUPS)
     * @param newImplementation Address of new implementation
     * @dev v1.6: Added validation to prevent accidental misconfiguration
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
        require(newImplementation.code.length > 0, "Implementation must be a contract");
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get listing details
     * @param listingId ID of the listing
     * @return Listing struct
     */
    function getListing(uint256 listingId) external view returns (Listing memory) {
        return listings[listingId];
    }

    /**
     * @notice Check if signature has been used
     * @param digest Signature digest
     * @return True if used
     */
    function isSignatureUsed(bytes32 digest) external view returns (bool) {
        return usedSignatures[digest];
    }

    /**
     * @notice Get bundle token IDs (external wrapper)
     * @param bundleType Type of bundle
     * @return tokenIds Array of token IDs
     */
    function getBundleTokenIds(BundleType bundleType) external pure returns (uint256[] memory tokenIds) {
        return _getBundleTokenIds(bundleType);
    }

    /**
     * @notice Get the inclusive day range [start, end] for a bundle type (v1.13).
     * @param bundleType Type of bundle
     * @return start First day token id
     * @return end Last day token id
     * @dev Public so off-chain consumers (indexer / frontend) can mirror the
     *      canonical ranges directly from the contract instead of duplicating
     *      the formula.
     */
    function getBundleDayRange(BundleType bundleType) external pure returns (uint256 start, uint256 end) {
        return _rangeForBundle(bundleType);
    }

    /**
     * @notice Get active listings with pagination (v1.3 - optimized with EnumerableSet)
     * @dev Uses activeListingIds set for O(1) count and direct access
     *      Gas cost is constant regardless of history (nextListingId)
     *      v1.11: Filters out expired listings
     * @param offset Starting index (applied AFTER filtering expired)
     * @param limit Maximum number of listings to return (capped at 100)
     * @return listingIds Array of listing IDs (non-expired only)
     * @return listingData Array of corresponding Listing structs
     * @return totalActive Total number of non-expired active listings
     */
    function getActiveListings(uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory listingIds, Listing[] memory listingData, uint256 totalActive)
    {
        require(limit > 0 && limit <= 100, "Invalid limit");

        uint256 totalInSet = activeListingIds.length();

        // First pass: count non-expired listings.
        // >= matches buyability: buyListing reverts only when block.timestamp >
        // expiresAt, so a listing is still buyable at its exact expiry second and
        // must stay visible here (audit MEDIUM-01: visible <=> buyable).
        uint256 nonExpiredCount = 0;
        for (uint256 i = 0; i < totalInSet; i++) {
            uint256 listingId = activeListingIds.at(i);
            if (listings[listingId].expiresAt >= block.timestamp) {
                nonExpiredCount++;
            }
        }

        totalActive = nonExpiredCount;

        // Handle edge cases
        if (nonExpiredCount == 0 || offset >= nonExpiredCount) {
            return (new uint256[](0), new Listing[](0), totalActive);
        }

        // Calculate actual return size
        uint256 returnSize = limit;
        if (offset + limit > nonExpiredCount) {
            returnSize = nonExpiredCount - offset;
        }

        // Allocate arrays
        listingIds = new uint256[](returnSize);
        listingData = new Listing[](returnSize);

        // Second pass: collect non-expired listings with offset/limit
        // (same >= boundary as the first pass — see note above).
        uint256 collected = 0;
        uint256 skipped = 0;
        for (uint256 i = 0; i < totalInSet && collected < returnSize; i++) {
            uint256 listingId = activeListingIds.at(i);
            if (listings[listingId].expiresAt >= block.timestamp) {
                if (skipped < offset) {
                    skipped++;
                } else {
                    listingIds[collected] = listingId;
                    listingData[collected] = listings[listingId];
                    collected++;
                }
            }
        }

        return (listingIds, listingData, totalActive);
    }
}
