#!/bin/bash

# Check balances of all test wallets on Base Sepolia
# Usage: ./scripts/check-balances.sh

RPC_URL="https://sepolia.base.org"

echo "==================================="
echo "   Base Sepolia Wallet Balances   "
echo "==================================="
echo ""

# Deployer
echo "🔧 Deployer (Owner)"
echo "Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BALANCE=$(cast balance 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url $RPC_URL --ether 2>/dev/null || echo "0")
echo "Balance: $BALANCE ETH"
echo ""

# Seller Year 1
echo "🎨 Seller Year 1"
echo "Address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BALANCE=$(cast balance 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --rpc-url $RPC_URL --ether 2>/dev/null || echo "0")
echo "Balance: $BALANCE ETH"
echo ""

# Seller Year 2
echo "🎨 Seller Year 2"
echo "Address: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
BALANCE=$(cast balance 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC --rpc-url $RPC_URL --ether 2>/dev/null || echo "0")
echo "Balance: $BALANCE ETH"
echo ""

# Seller Incomplete
echo "⚠️  Seller Incomplete"
echo "Address: 0x90F79bf6EB2c4f870365E785982E1f101E93b906"
BALANCE=$(cast balance 0x90F79bf6EB2c4f870365E785982E1f101E93b906 --rpc-url $RPC_URL --ether 2>/dev/null || echo "0")
echo "Balance: $BALANCE ETH"
echo ""

# Buyer Alice
echo "💰 Buyer Alice"
echo "Address: 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
BALANCE=$(cast balance 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65 --rpc-url $RPC_URL --ether 2>/dev/null || echo "0")
echo "Balance: $BALANCE ETH"
echo ""

# Buyer Bob
echo "💰 Buyer Bob"
echo "Address: 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"
BALANCE=$(cast balance 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc --rpc-url $RPC_URL --ether 2>/dev/null || echo "0")
echo "Balance: $BALANCE ETH"
echo ""

echo "==================================="
echo "Faucets to get testnet ETH:"
echo "https://docs.base.org/docs/tools/network-faucets/"
echo "==================================="
