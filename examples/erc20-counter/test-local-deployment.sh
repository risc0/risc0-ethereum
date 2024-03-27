#!/bin/bash

cleanup() {
    echo "Cleaning up..."
    # Check if Ganache PID is set and if the process is running, then kill it
    if [ ! -z "$GANACHE_PID" ]; then
        if ps -p $GANACHE_PID > /dev/null; then
            echo "Killing Ganache (PID $GANACHE_PID)..."
            kill $GANACHE_PID
        fi
    fi
}

# Trap EXIT and ERR signals to call the cleanup function
# This ensures cleanup is performed on script exit or error
trap cleanup EXIT ERR

# Start Ganache and capture its output temporarily
ganache > ganache_logs.txt 2>&1 &
GANACHE_PID=$!
echo "Ganache started with PID $GANACHE_PID"

# Wait a few seconds to ensure Ganache has started and output private keys
sleep 5

# Extract the first private key from the Ganache logs
ETH_WALLET_PRIVATE_KEY=$(grep -A 10 "Private Keys" ganache_logs.txt | grep -o '0x.*' | head -n 1)

if [ -z "$ETH_WALLET_PRIVATE_KEY" ]; then
    echo "Failed to extract ETH_WALLET_PRIVATE_KEY from Ganache logs."
    exit 1
else
    echo "Extracted ETH_WALLET_PRIVATE_KEY from Ganache logs: $ETH_WALLET_PRIVATE_KEY"
fi

export ETH_WALLET_PRIVATE_KEY=$ETH_WALLET_PRIVATE_KEY

# Directly use the environment variables for BONSAI_API_KEY and BONSAI_API_URL
if [ -z "$BONSAI_API_KEY" ] || [ -z "$BONSAI_API_URL" ]; then
    echo "Please ensure BONSAI_API_KEY and BONSAI_API_URL are set in your environment."
    exit 1
fi


# Deploy the ERC20 Toyken contract
echo "Deploying ERC20 Toyken contract..."
forge script --rpc-url http://localhost:8545 --broadcast script/DeployERC20.s.sol

# Extract the Toyken address
export TOYKEN_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "ERC20") | .contractAddress' ./broadcast/DeployERC20.s.sol/1337/run-latest.json)
echo "ERC20 Toyken Address: $TOYKEN_ADDRESS"

# Mint Toyken to a specific address
echo "Minting Toyken to 0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4..."
cast send --private-key $ETH_WALLET_PRIVATE_KEY --rpc-url http://localhost:8545 $TOYKEN_ADDRESS 'mint(address, uint256)' 0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4 100

# Strip '0x' prefix from TOYKEN_ADDRESS, if it exists
STRIPPED_TOYKEN_ADDRESS=${TOYKEN_ADDRESS#0x}

files=(
    "apps/src/bin/publisher.rs"
    "methods/guest/src/bin/balance_of.rs"
)

# Loop through each file and use Perl for in-place editing
for file in "${files[@]}"; do
    perl -pi -e "s/address!\(\"[a-zA-Z0-9]*\"\)/address!(\"$STRIPPED_TOYKEN_ADDRESS\")/g" "$file"
done

# Build the project
echo "Building the project..."
cargo build

# Deploy the Counter contract
echo "Deploying the Counter contract..."
forge script --rpc-url http://localhost:8545 --broadcast script/DeployCounter.s.sol

# Extract the Counter contract address
export COUNTER_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/DeployCounter.s.sol/1337/run-latest.json)
echo "Counter Address: $COUNTER_ADDRESS"

# Publish a new state
echo "Publishing a new state..."
cargo run --bin publisher -- \
    --chain-id=1337 \
    --rpc-url=http://localhost:8545 \
    --contract=${COUNTER_ADDRESS:?} \
    --account=0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4

# Attempt to verify counter value as part of the script logic
COUNTER_VALUE=$(cast call --rpc-url http://localhost:8545 ${COUNTER_ADDRESS:?} 'get()(uint256)')
if [ "$COUNTER_VALUE" != "1" ]; then
    echo "Counter value is not 1 as expected, but $COUNTER_VALUE."
    exit 1
fi

echo "All operations completed successfully."
