// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title BasePaintMarket (Non-Upgradeable)
 * @notice NFT marketplace for trading complete BasePaint year bundles on Base L2
 * @dev Non-upgradeable version for simpler deployment via Remix
 * @dev Based on v1.11 - all business logic identical to upgradeable version
 * @custom:security-contact security@basepaintmarket.xyz
 */
contract BasePaintMarket is
    ReentrancyGuard,
    Pausable,
    Ownable2Step,
    EIP712
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

    /// @notice Bundle types available for trading
    enum BundleType {
        YEAR_1, // Days 1-365 (365 NFTs)
        YEAR_2 // Days 366-730 (365 NFTs)
    }

    /// @notice Listing structure
    struct Listing {
        address seller;
        BundleType bundleType;
        uint256 price;
        uint256 createdAt;
        bool active;
        uint256 expiresAt;
    }

    /// @notice Collection offer parameters for EIP-712 signature
    struct CollectionOfferParams {
        address buyer;
        BundleType bundleType;
        uint256 price;
        uint256 expiresAt;
        uint256 salt;
        uint256 nonce;
    }

    /// @notice Mapping of listing ID to Listing
    mapping(uint256 => Listing) public listings;

    /// @notice Mapping to track active listing per user per bundle type (prevents duplicates)
    mapping(address => mapping(BundleType => uint256)) public activeListingByUser;

    /// @notice Mapping to track used offer signatures (prevent replay)
    mapping(bytes32 => bool) public usedSignatures;

    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklist;

    /// @notice Set of active listing IDs
    EnumerableSet.UintSet private activeListingIds;

    /// @notice Mapping of offer nonces per user (for on-chain offer cancellation)
    mapping(address => uint256) public offerNonces;

    /// @notice Maximum length for emergency message
    uint256 public constant MAX_EMERGENCY_MESSAGE_LENGTH = 500;

    // EIP-712 typehash for collection offers
    bytes32 public constant COLLECTION_OFFER_TYPEHASH =
        keccak256("CollectionOffer(address buyer,uint8 bundleType,uint256 price,uint256 expiresAt,uint256 salt,uint256 nonce)");

    /// @notice Maximum batch size for cleanupExpiredListings
    uint256 public constant MAX_CLEANUP_BATCH = 100;

    // ============================================
    // EVENTS
    // ============================================

    event ListingCreated(
        uint256 indexed listingId, address indexed seller, BundleType bundleType, uint256 price, uint256 expiresAt, uint256 timestamp
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
    error ListingExpired();
    error ListingNotExpired();
    error NothingToWithdraw();
    error InvalidAmount();
    error OfferNonceMismatch();
    error EmergencyMessageTooLong();

    // ============================================
    // MODIFIERS
    // ============================================

    modifier notBlacklisted() {
        if (blacklist[msg.sender]) revert Blacklisted();
        _;
    }

    // ============================================
    // CONSTRUCTOR
    // ============================================

    /**
     * @notice Initialize the contract
     * @param _basePaint Address of BasePaint ERC1155 contract
     * @param _weth Address of weth token contract
     * @param _initialOwner Address of initial owner
     */
    constructor(address _basePaint, address _weth, address _initialOwner)
        Ownable(_initialOwner)
        EIP712("BasePaintMarket", "1")
    {
        require(_basePaint != address(0), "BasePaint address cannot be zero");
        require(_weth != address(0), "WETH address cannot be zero");

        basePaint = IERC1155(_basePaint);
        weth = IERC20(_weth);
        platformFee = 200; // 2%
        minListingPrice = 1 ether;
        nextListingId = 1;
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
    function createListing(BundleType bundleType, uint256 price, uint256 duration) external whenNotPaused notBlacklisted {
        if (price < minListingPrice) revert PriceTooLow();
        if (duration < MIN_LISTING_DURATION || duration > MAX_LISTING_DURATION) revert InvalidDuration();

        // Check for existing listing and auto-cleanup if expired
        uint256 existingListingId = activeListingByUser[msg.sender][bundleType];
        if (existingListingId != 0) {
            Listing storage existing = listings[existingListingId];
            if (existing.active) {
                // If expired - auto cleanup
                if (block.timestamp > existing.expiresAt) {
                    existing.active = false;
                    activeListingIds.remove(existingListingId);
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

        // Add to active listings set
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

        listing.active = false;

        // Clear active listing mapping
        delete activeListingByUser[msg.sender][listing.bundleType];

        // Remove from active listings set
        activeListingIds.remove(listingId);

        emit ListingCancelled(listingId, listing.bundleType, block.timestamp);
    }

    /**
     * @notice Buy a listing at fixed price
     * @param listingId ID of the listing to purchase
     */
    function buyListing(uint256 listingId) external payable nonReentrant whenNotPaused notBlacklisted {
        Listing storage listing = listings[listingId];

        if (!listing.active) revert ListingNotActive();
        if (block.timestamp > listing.expiresAt) revert ListingExpired();
        if (msg.value < listing.price) revert InsufficientPayment();

        // Prevent trading with blacklisted sellers
        if (blacklist[listing.seller]) revert Blacklisted();

        // Validate approval still active (before expensive validation)
        if (!basePaint.isApprovedForAll(listing.seller, address(this))) {
            revert NotApproved();
        }

        // Validate bundle ownership (fail fast with MissingToken error before state changes)
        _validateBundleOwnership(listing.seller, listing.bundleType);

        // Deactivate listing
        listing.active = false;

        // Clear active listing mapping
        delete activeListingByUser[listing.seller][listing.bundleType];

        // Remove from active listings set
        activeListingIds.remove(listingId);

        // CRITICAL: Validate bundle integrity AND transfer in single call
        _validateAndTransferBundle(listing.seller, msg.sender, listing.bundleType);

        // Distribute payment
        _distributeFunds(listing.seller, listing.price);

        emit ListingSold(
            listingId, msg.sender, listing.seller, listing.bundleType, listing.price, (listing.price * platformFee) / 10000, block.timestamp
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

        // Prevent trading with blacklisted buyers
        if (blacklist[offer.buyer]) revert Blacklisted();

        // Validate expiration
        if (block.timestamp > offer.expiresAt) revert OfferExpired();

        // Validate offer nonce matches current user nonce
        if (offer.nonce != offerNonces[offer.buyer]) revert OfferNonceMismatch();

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                COLLECTION_OFFER_TYPEHASH, offer.buyer, offer.bundleType, offer.price, offer.expiresAt, offer.salt, offer.nonce
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

        // Validate bundle ownership (fail fast with MissingToken error before state changes)
        _validateBundleOwnership(msg.sender, offer.bundleType);

        // Cancel any active listing from seller for this bundle type
        uint256 existingListingId = activeListingByUser[msg.sender][offer.bundleType];
        if (existingListingId != 0 && listings[existingListingId].active) {
            listings[existingListingId].active = false;
            delete activeListingByUser[msg.sender][offer.bundleType];
            activeListingIds.remove(existingListingId);
            emit ListingCancelled(existingListingId, offer.bundleType, block.timestamp);
        }

        // Calculate fee and seller amount
        uint256 fee = (offer.price * platformFee) / 10000;
        uint256 sellerAmount = offer.price - fee;

        // Transfer WETH first (fail-fast: prevents wasted gas on 365 NFT transfers)
        weth.safeTransferFrom(offer.buyer, address(this), offer.price);

        // CRITICAL: Validate bundle integrity AND transfer in single call
        _validateAndTransferBundle(msg.sender, offer.buyer, offer.bundleType);

        // Accumulate WETH fees
        platformFeesAccumulatedWETH += fee;

        // Transfer seller amount from contract to seller
        weth.safeTransfer(msg.sender, sellerAmount);

        emit CollectionOfferAccepted(
            offer.buyer, msg.sender, offer.bundleType, offer.price, fee, block.timestamp, offer.salt
        );
    }

    // ============================================
    // OFFER CANCELLATION
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
    // CLEANUP FUNCTIONS
    // ============================================

    /**
     * @notice Clean up a single expired listing
     * @param listingId ID of the expired listing to clean up
     * @dev Anyone can call this - helps keep EnumerableSet clean
     * @dev Intentionally permissionless - ecosystem cleanup benefits all participants
     */
    function cleanupExpiredListing(uint256 listingId) external whenNotPaused {
        Listing storage listing = listings[listingId];
        if (!listing.active) revert ListingNotActive();
        if (block.timestamp <= listing.expiresAt) revert ListingNotExpired();

        listing.active = false;
        delete activeListingByUser[listing.seller][listing.bundleType];
        activeListingIds.remove(listingId);

        emit ListingExpiredAndCleaned(listingId, listing.bundleType, block.timestamp);
    }

    /**
     * @notice Clean up multiple expired listings in one transaction
     * @param listingIds Array of listing IDs to clean up (max 100)
     * @dev Silently skips invalid/non-expired listings for gas efficiency
     * @dev Intentionally permissionless - ecosystem cleanup benefits all participants
     */
    function cleanupExpiredListings(uint256[] calldata listingIds) external whenNotPaused {
        require(listingIds.length <= MAX_CLEANUP_BATCH, "Batch too large");
        for (uint256 i = 0; i < listingIds.length; i++) {
            Listing storage listing = listings[listingIds[i]];
            if (listing.active && block.timestamp > listing.expiresAt) {
                listing.active = false;
                delete activeListingByUser[listing.seller][listing.bundleType];
                activeListingIds.remove(listingIds[i]);
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
     * @notice Set minimum listing price
     * @param newPrice New minimum price in wei
     */
    function setMinListingPrice(uint256 newPrice) external onlyOwner {
        uint256 oldPrice = minListingPrice;
        minListingPrice = newPrice;

        emit MinListingPriceUpdated(oldPrice, newPrice);
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
     * @notice Validate that address owns complete bundle
     * @dev Uses balanceOfBatch for gas optimization
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
     * @notice Get token IDs for bundle type
     * @param bundleType Type of bundle
     * @return tokenIds Array of token IDs in the bundle
     */
    function _getBundleTokenIds(BundleType bundleType) internal pure returns (uint256[] memory tokenIds) {
        if (bundleType == BundleType.YEAR_1) {
            tokenIds = new uint256[](365);
            for (uint256 i = 0; i < 365; i++) {
                tokenIds[i] = i + 1;
            }
        } else if (bundleType == BundleType.YEAR_2) {
            tokenIds = new uint256[](365);
            for (uint256 i = 0; i < 365; i++) {
                tokenIds[i] = i + 366; // Days 366-730
            }
        } else {
            revert InvalidBundleType();
        }
    }

    /**
     * @notice Transfer complete bundle from seller to buyer
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
     * @notice Get active listings with pagination
     * @dev Filters out expired listings
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

        // First pass: count non-expired listings
        uint256 nonExpiredCount = 0;
        for (uint256 i = 0; i < totalInSet; i++) {
            uint256 listingId = activeListingIds.at(i);
            if (listings[listingId].expiresAt > block.timestamp) {
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
        uint256 collected = 0;
        uint256 skipped = 0;
        for (uint256 i = 0; i < totalInSet && collected < returnSize; i++) {
            uint256 listingId = activeListingIds.at(i);
            if (listings[listingId].expiresAt > block.timestamp) {
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
