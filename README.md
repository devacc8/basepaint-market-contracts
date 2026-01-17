# BasePaint Bundle Marketplace - Smart Contracts

Smart contracts for BasePaint Bundle Marketplace on Base L2. Trade complete BasePaint year collections (365 NFTs) in single transactions.

## Overview

BasePaint Bundle Marketplace enables trading of complete year bundles:
- **Year 1**: Days 1-365 (365 NFTs)
- **Year 2**: Days 366-730 (365 NFTs)

## Features

- **Approval-Based Listings**: NFTs remain with seller until purchase (OpenSea pattern)
- **WETH Offers**: Off-chain EIP-712 signatures, zero gas for offer creation
- **Bundle Validation**: Atomic validation of all 365 NFTs at purchase time
- **Security First**: ReentrancyGuard, Pausable, comprehensive access control
- **UUPS Upgradeable**: Proxy pattern for future improvements

## Contract Addresses

### Base Mainnet

| Contract | Address |
|----------|---------|
| **Marketplace Proxy** | [`0xB0897037052BB9104CcDF743358ea4f91990A362`](https://basescan.org/address/0xB0897037052BB9104CcDF743358ea4f91990A362) |
| **BasePaint NFT** | [`0xba5e05cb26b78eda3a2f8e3b3814726305dcac83`](https://basescan.org/address/0xba5e05cb26b78eda3a2f8e3b3814726305dcac83) |
| **WETH** | [`0x4200000000000000000000000000000000000006`](https://basescan.org/address/0x4200000000000000000000000000000000000006) |

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

## Architecture

```
src/
├── BasePaintMarket.sol     # Main marketplace contract (UUPS upgradeable)
└── mocks/
    ├── MockBasePaint.sol   # Mock ERC1155 for testing
    └── MockWETH.sol        # Mock WETH for testing

test/
├── BasePaintMarket.t.sol      # Unit tests
└── BasePaintMarketFuzz.t.sol  # Fuzz tests
```

## Security

- **Audit Status**: Internal audit completed (v1.11, score 9.0/10)
- **Bug Bounty**: Contact via GitHub issues

### Security Features

- ReentrancyGuard on all state-changing functions
- Pausable for emergency stops
- Ownable2Step for secure ownership transfer
- Buyer blacklist for compliance
- Minimum price requirements

## License

MIT License - see [LICENSE](LICENSE)

## Links

- **Website**: [basepaint.market](https://basepaint.market)
- **BasePaint**: [basepaint.xyz](https://basepaint.xyz)
- **Base**: [base.org](https://base.org)
