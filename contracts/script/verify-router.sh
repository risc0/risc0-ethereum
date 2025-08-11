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
export ADMIN_ADDRESS=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].admin" $CONTRACTS_DIR/deployment.toml)
export TIMELOCK_CONTROLLER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].timelock-controller" $CONTRACTS_DIR/deployment.toml)
export VERIFIER_ROUTER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].router" $CONTRACTS_DIR/deployment.toml)
export MIN_DELAY=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].timelock-delay" $CONTRACTS_DIR/deployment.toml)


# NOTE: forge verify-contract seems to fail if an absolute path is used for the contract address.
cd $CONTRACTS_DIR

# Run forge build to ensure artifacts are available and built with the right options.
forge build

CONSTUCTOR_ARGS="$(\
    cast abi-encode 'constructor(address)' \
    ${TIMELOCK_CONTROLLER:?} \
)"
forge verify-contract --watch \
    --chain-id=${CHAIN_ID:?} \
    --constructor-args=${CONSTUCTOR_ARGS} \
    --etherscan-api-key=${ETHERSCAN_API_KEY:?} \
    ${VERIFIER_ROUTER:?} \
    ./src/RiscZeroVerifierRouter.sol:RiscZeroVerifierRouter

CONSTRUCTOR_ARGS="$(\
    cast abi-encode 'constructor(uint256,address[],address[],address)' \
    ${MIN_DELAY:?} \
    ${PROPOSERS:?} \
    ${EXECUTORS:?} \
    ${ADMIN:?} \
)"
forge verify-contract --watch \
    --chain-id=${CHAIN_ID:?} \
    --constructor-args=${CONSTRUCTOR_ARGS:?} \
    --etherscan-api-key=${ETHERSCAN_API_KEY:?} \
    ${TIMELOCK_CONTROLLER:?} \
    ../lib/openzeppelin-contracts/contracts/governance/TimelockController.sol:TimelockController
