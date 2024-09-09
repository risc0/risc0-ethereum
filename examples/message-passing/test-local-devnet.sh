#!/bin/bash
set -e -o pipefail

. .env

forge script --broadcast Deploy

L1_CROSS_DOMAIN_MESSENGER_ADDRESS=$(jq -re '[.deployments[].transactions[] | select(.contractName == "L1CrossDomainMessenger")][0] | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)
L2_CROSS_DOMAIN_MESSENGER_ADDRESS=$(jq -re '[.deployments[].transactions[] | select(.contractName == "L2CrossDomainMessenger")][0] | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)
COUNTER_ADDRESS=$(jq -re '.deployments[].transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)

CALL_DATA=$(cast cd 'increment()')

echo "L1CrossDomainMessenger.sendMessage..."
SEND_MESSAGE_RECEIPT=$(cast send --rpc-url $L1_RPC_URL --private-key $L1_WALLET_PRIVATE_KEY --json $L1_CROSS_DOMAIN_MESSENGER_ADDRESS 'sendMessage(address target, bytes calldata data)' $COUNTER_ADDRESS $CALL_DATA)
SEND_MESSAGE_TX_HASH=$(echo $SEND_MESSAGE_RECEIPT | jq -re '.transactionHash')
cast run --rpc-url $L1_RPC_URL $SEND_MESSAGE_TX_HASH

START_TIME=$(date +%s)

RELAY_MESSAGE_ARGS="$(RUST_LOG=warn cargo run -- \
  --rpc-url ${L1_RPC_URL:?} \
  --beacon-api-url ${BEACON_API_URL:?} \
  --cross-domain-messenger-address=${L1_CROSS_DOMAIN_MESSENGER_ADDRESS:?} \
  --tx-hash ${SEND_MESSAGE_TX_HASH:?})"

EXECUTION_TIME=$((`date +%s` - START_TIME))
if [ $EXECUTION_TIME -lt 12 ]; then
    sleep $((12 - EXECUTION_TIME))
fi

echo "L2CrossDomainMessenger.relayMessage..."
RELAY_MESSAGE_RECEIPT=$(cast send --rpc-url $L2_RPC_URL --private-key $L2_WALLET_PRIVATE_KEY --json $L2_CROSS_DOMAIN_MESSENGER_ADDRESS 'relayMessage(bytes,bytes)' $RELAY_MESSAGE_ARGS)
RELAY_MESSAGE_TX_HASH=$(echo $RELAY_MESSAGE_RECEIPT | jq -re '.transactionHash')
cast run --rpc-url $L2_RPC_URL $RELAY_MESSAGE_TX_HASH

echo "Verifying state..."
COUNTER_VALUE=$(cast call --rpc-url $L2_RPC_URL ${COUNTER_ADDRESS:?} 'get()(uint256)')
if [ "$COUNTER_VALUE" != "1" ]; then
    echo "Counter value is not 1 as expected, but $COUNTER_VALUE."
    exit 1
fi
