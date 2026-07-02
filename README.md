# BasePaint Bundle Marketplace - Smart Contracts

Smart contracts for BasePaint Bundle Marketplace on Base L2. Trade complete BasePaint collections — full years (365 NFTs) and monthly sets (30 days) — in single atomic transactions.

## Overview

BasePaint Bundle Marketplace enables trading of complete BasePaint sets in one transaction. **26 bundle types (v1.13):**
- **Year 1** / **Year 2** — full-year sets: days 1–365 / 366–730 (365 NFTs each)
- **24 monthly (mini) sets** (`mini-1` … `mini-24`) — 30-day slices of each year, except each year's closing month (`mini-12`, `mini-24`) which runs 35 days. Ranges are derived on-chain by `_rangeForBundle`; the enum is fixed and append-only.

**v1.14 (LIVE on Base mainnet, 2026-07-02):** three logic-only changes, no storage
change — (1) a `SelfTrade` guard on `buyListing` / `acceptCollectionOffer` (a
party can no longer wash-trade with itself); (2) a `getActiveListings` expiry
boundary fix (`>=` so a listing stays visible through its exact expiry second,
matching buyability); (3) **EIP-1271 offers** — `acceptCollectionOffer` uses
OpenZeppelin `SignatureChecker`, so smart-contract wallets (e.g. Coinbase Smart
Wallet, common on Base) can have their collection offers accepted, not just EOAs.

## Features

- **Approval-Based Listings**: NFTs remain with seller until purchase (OpenSea pattern)
- **Year & Monthly Sets**: 26 bundle types — full years (365 NFTs) or 30-day monthly slices — with on-chain range validation
- **WETH Offers**: Off-chain EIP-712 signatures, zero gas for offer creation
- **Bundle Validation**: Atomic validation of every NFT in the set (365 for a year, 30/35 for a month) at purchase time
- **Security First**: ReentrancyGuard, Pausable, comprehensive access control
- **UUPS Upgradeable**: Proxy pattern for future improvements

## Contract Addresses

### Base Mainnet

| Contract | Address |
|----------|---------|
| **Marketplace Proxy** (UUPS) | [`0xB0897037052BB9104CcDF743358ea4f91990A362`](https://basescan.org/address/0xB0897037052BB9104CcDF743358ea4f91990A362) |
| **Implementation** (v1.14) | [`0xb64Cbe9D32bA923119D9ab95Ae3a794EFa8Ffe1A`](https://basescan.org/address/0xb64Cbe9D32bA923119D9ab95Ae3a794EFa8Ffe1A#code) |
| **BasePaint NFT** | [`0xba5e05cb26b78eda3a2f8e3b3814726305dcac83`](https://basescan.org/address/0xba5e05cb26b78eda3a2f8e3b3814726305dcac83) |
| **WETH** | [`0x4200000000000000000000000000000000000006`](https://basescan.org/address/0x4200000000000000000000000000000000000006) |

> `src/BasePaintMarket.sol` in this repo is the **v1.14 production source** and
> matches the deployed implementation above (live on Base mainnet since 2026-07-02).
> v1.14 added a self-trade guard, a `getActiveListings` expiry-boundary fix, and
> EIP-1271 smart-contract-wallet offer support — a pure-logic swap (no storage change).

## Development

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Setup

```bash
# Clone repository
git clone https://github.com/devacc8/basepaint-market-contracts.git
cd basepaint-market-contracts

# Install dependencies
forge install

# Build
forge build

# Run tests
forge test

# Run tests with verbosity
forge test -vvv
```

### Test Coverage

```bash
forge coverage
```

## Contract Variants

This repository includes two versions of the marketplace contract:

| Contract | Description | Use Case |
|----------|-------------|----------|
| `BasePaintMarket.sol` | UUPS Upgradeable | **Production** (v1.14) — the deployed & audited contract |
| `BasePaintMarketFlat.sol` | Non-upgradeable | Legacy Remix/immutable reference — **lags production** (no v1.13 mini-sets, no v1.14 changes) |

### Differences

**BasePaintMarket.sol (Upgradeable)**
- Uses OpenZeppelin Upgradeable contracts
- Deployed via UUPS proxy pattern
- Can be upgraded by owner
- `initialize()` function instead of constructor

**BasePaintMarketFlat.sol (Non-upgradeable)**
- Uses standard OpenZeppelin contracts
- Direct deployment (no proxy)
- Immutable after deployment
- Standard `constructor()`

## Architecture

```
src/
├── BasePaintMarket.sol      # Main contract (UUPS upgradeable)
├── BasePaintMarketFlat.sol  # Non-upgradeable version
└── mocks/
    ├── MockBasePaint.sol    # Mock ERC1155 for testing
    └── MockWETH.sol         # Mock WETH for testing

test/
├── BasePaintMarket.t.sol      # Unit tests
└── BasePaintMarketFuzz.t.sol  # Fuzz tests
```

## Security

- **Audit Status**: v1.11 audited (9.0/10); v1.13 mini-set upgrade re-audited 2026-06 (0 critical/high); v1.14 (self-trade guard, expiry-boundary fix, EIP-1271 offers) live on mainnet 2026-07 (Fable full audit 9.0/10; EIP-1271 addition covered by unit + fork-sim tests)
- **Bug Bounty**: Contact via GitHub issues

### Security Features

- ReentrancyGuard on all state-changing functions
- Pausable for emergency stops
- Ownable2Step for secure ownership transfer
- Buyer blacklist for compliance
- Minimum price requirements (separate floors for year vs mini sets)
- Fixed, append-only bundle enum — no arbitrary ranges

## License

MIT License - see [LICENSE](LICENSE)

## Links

- **Website**: [basepaint.market](https://basepaint.market)
- **BasePaint**: [basepaint.xyz](https://basepaint.xyz)
- **Base**: [base.org](https://base.org)
