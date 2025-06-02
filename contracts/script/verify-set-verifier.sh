#!/bin/bash

set -eo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CONTRACTS_DIR="${SCRIPT_DIR:?}/.."

if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo -n 'ETHERSCAN_API_KEY from deployment_secrets.toml: ' > /dev/stderr
    export ETHERSCAN_API_KEY=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].etherscan-api-key" $CONTRACTS_DIR/deployment_secrets.toml)
else
    echo -n "ETHERSCAN_API_KEY from env $ETHERSCAN_API_KEY"
fi

export CHAIN_ID=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].id" $CONTRACTS_DIR/deployment.toml)
export VERIFIER_ADDRESS=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\").verifier" $CONTRACTS_DIR/deployment.toml)
export ESTOP_ADDRESS=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\").estop" $CONTRACTS_DIR/deployment.toml)
export ADMIN_ADDRESS=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].admin" $CONTRACTS_DIR/deployment.toml)

export CHAIN_ID=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].id" $CONTRACTS_DIR/deployment.toml)

export VERIFIER_ROUTER_ADDRESS=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].router" $CONTRACTS_DIR/deployment.toml)
export SET_BUILDER_IMAGE_ID=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\").set-builder-image-id" $CONTRACTS_DIR/deployment.toml)
export SET_BUILDER_ELF_URL=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\").set-builder-elf-url" $CONTRACTS_DIR/deployment.toml)

# NOTE: forge verify-contract seems to fail if an absolute path is used for the contract address.
cd $CONTRACTS_DIR

CONSTRUCTOR_ARGS="$(\
    cast abi-encode 'constructor(address,bytes32,string)' \
    "${VERIFIER_ROUTER_ADDRESS:?}" \
    "${SET_BUILDER_IMAGE_ID:?}" \
    "${SET_BUILDER_ELF_URL:?}" \
)"
forge verify-contract --watch \
    --chain-id=${CHAIN_ID:?} \
    --constructor-args=${CONSTRUCTOR_ARGS:?} \
    --etherscan-api-key=${ETHERSCAN_API_KEY:?} \
    ${VERIFIER_ADDRESS:?} \
    ./src/RiscZeroSetVerifier.sol:RiscZeroSetVerifier

CONSTRUCTOR_ARGS="$(\
    cast abi-encode 'constructor(address,address)' \
    ${VERIFIER_ADDRESS:?} \
    ${ADMIN_ADDRESS:?} \
)"
forge verify-contract --watch \
    --chain-id=${CHAIN_ID:?} \
    --constructor-args=${CONSTRUCTOR_ARGS:?} \
    --etherscan-api-key=${ETHERSCAN_API_KEY:?} \
    ${ESTOP_ADDRESS:?} \
    ./src/RiscZeroVerifierEmergencyStop.sol:RiscZeroVerifierEmergencyStop
