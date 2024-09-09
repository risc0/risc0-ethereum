#!/bin/bash
set -e -o pipefail

. .env

echo "Deploy contracts..."
forge script --broadcast Deploy

L1_CROSS_DOMAIN_MESSENGER_ADDRESS=$(jq -re '[.deployments[].transactions[] | select(.contractName == "L1CrossDomainMessenger")][0] | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)
L2_CROSS_DOMAIN_MESSENGER_ADDRESS=$(jq -re '[.deployments[].transactions[] | select(.contractName == "L2CrossDomainMessenger")][0] | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)
COUNTER_ADDRESS=$(jq -re '.deployments[].transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)

# call 'Counter.increment()' on the L2
CALL_DATA=$(cast cd 'increment()')

echo "L1CrossDomainMessenger.sendMessage..."
SEND_MESSAGE_RECEIPT=$(cast send --rpc-url "${L1_RPC_URL:?}" --private-key "${L1_WALLET_PRIVATE_KEY:?}" --json "$L1_CROSS_DOMAIN_MESSENGER_ADDRESS" 'sendMessage(address, bytes)' "$COUNTER_ADDRESS" "$CALL_DATA")
echo "$SEND_MESSAGE_RECEIPT" | jq
SEND_MESSAGE_TX_HASH=$(echo "$SEND_MESSAGE_RECEIPT" | jq -re '.transactionHash')

echo "Create proof..."
RUST_LOG=info,risc0_steel=debug cargo run -- \
  --l2-wallet-private-key "${L2_WALLET_PRIVATE_KEY:?}" \
  --l1-rpc-url "${L1_RPC_URL:?}" \
  --l2-rpc-url "${L2_RPC_URL:?}" \
  --l1-cross-domain-messenger-address="$L1_CROSS_DOMAIN_MESSENGER_ADDRESS" \
  --l2-cross-domain-messenger-address="$L2_CROSS_DOMAIN_MESSENGER_ADDRESS" \
  --tx-hash "$SEND_MESSAGE_TX_HASH" \
  --output "proof.json"
RELAY_MESSAGE_ARGS=$(jq -re '[.journal, .seal] | @tsv | sub("\t";" ";"g")' proof.json)

echo "L2CrossDomainMessenger.relayMessage..."
cast send --rpc-url "${L2_RPC_URL:?}" --private-key "${L2_WALLET_PRIVATE_KEY:?}" --json "${L2_CROSS_DOMAIN_MESSENGER_ADDRESS:?}" 'relayMessage(bytes, bytes)' $RELAY_MESSAGE_ARGS | jq

echo "Verifying L2 state..."
COUNTER_VALUE=$(cast call --rpc-url "${L2_RPC_URL:?}" "$COUNTER_ADDRESS" 'get()(uint256)')
if [ "$COUNTER_VALUE" != "1" ]; then
    echo "Counter value is not 1 as expected, but $COUNTER_VALUE."
    exit 1
fi
