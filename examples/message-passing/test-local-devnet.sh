#!/bin/bash

forge script --broadcast Deploy

L1_CROSS_DOMAIN_MESSENGER_ADDRESS=$(jq -re '[.deployments[].transactions[] | select(.contractName == "L1CrossDomainMessenger")][0] | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)
L2_CROSS_DOMAIN_MESSENGER_ADDRESS=$(jq -re '[.deployments[].transactions[] | select(.contractName == "L2CrossDomainMessenger")][0] | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)
COUNTER_ADDRESS=$(jq -re '.deployments[].transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/multi/Deploy.s.sol-latest/run.json)

RUST_LOG=info cargo run -- \
  --counter-address=$COUNTER_ADDRESS \
  --l1-cross-domain-messenger-address=$L1_CROSS_DOMAIN_MESSENGER_ADDRESS \
  --l2-cross-domain-messenger-address=$L2_CROSS_DOMAIN_MESSENGER_ADDRESS

echo "Verifying state..."
COUNTER_VALUE=$(cast call --rpc-url http://localhost:9545 ${COUNTER_ADDRESS:?} 'get()(uint256)')
if [ "$COUNTER_VALUE" != "1" ]; then
    echo "Counter value is not 1 as expected, but $COUNTER_VALUE."
    exit 1
fi
