#!/bin/bash
set -e -o pipefail

export TOKEN_OWNER=${ETH_WALLET_ADDRESS:?}

# Determine the chain ID
CHAIN_ID=$(cast rpc --rpc-url ${ETH_RPC_URL:?} eth_chainId | jq -re)
CHAIN_ID=$((CHAIN_ID))

# Deploy the Counter contract
echo "Deploying the Counter contract..."
forge script --rpc-url ${ETH_RPC_URL:?} --private-key ${ETH_WALLET_PRIVATE_KEY:?} --broadcast DeployCounter

# Extract the Toyken address
TOYKEN_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "ERC20FixedSupply") | .contractAddress' ./broadcast/DeployCounter.s.sol/$CHAIN_ID/run-latest.json)
echo "ERC20 Toyken Address: $TOYKEN_ADDRESS"

# Extract the Counter contract address
COUNTER_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/DeployCounter.s.sol/$CHAIN_ID/run-latest.json)
echo "Counter Address: $COUNTER_ADDRESS"

# Publish a new state
echo "Publishing a new state..."
RUST_LOG=info,risc0_steel=debug cargo run --bin publisher -- \
    --eth-wallet-private-key=${ETH_WALLET_PRIVATE_KEY:?} \
    --eth-rpc-url=${ETH_RPC_URL:?} \
    --counter=${COUNTER_ADDRESS:?} \
    --token-contract=${TOYKEN_ADDRESS:?} \
    --account=${TOKEN_OWNER:?}

# Attempt to verify counter value as part of the script logic
echo "Verifying state..."
COUNTER_VALUE=$(cast call --rpc-url ${ETH_RPC_URL:?} ${COUNTER_ADDRESS:?} 'get()(uint256)')
if [ "$COUNTER_VALUE" != "1" ]; then
    echo "Counter value is not 1 as expected, but $COUNTER_VALUE."
    exit 1
fi
