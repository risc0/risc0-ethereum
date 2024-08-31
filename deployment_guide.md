# Verifier Contracts Operation Guide

> TODO: Merge this guide into contracts/script/README.md

## Configuration

Configurations and deployment state information is stored in `deployment.toml`.
It contains information about each chain (e.g. name, ID, Etherscan URL), and addresses for the timelock, router, and verifier contracts on each chain.

Accompanying the `deployment.toml` file is a `deployment_secrets.toml` file with the following schema.
It is used to store somewhat sensative API keys for RPC services and Etherscan.
Note that it does not contain private keys or API keys for Fireblocks.
It should never be committed to `git`, and the API keys should be rotated if this occurs.

```toml
[chains.$CHAIN_KEY]
rpc-url = "..."
etherscan-api-key = "..."
```

## Environment

Operations require a number of environment variables to be set.

* Set environment vars that are stable across chains:

    These variables are stable across chains within the same class (i.e. testnet vs mainnet).

    > NOTE: Fireblocks only supports RSA for API request signing.
    > FIREBLOCKS_API_PRIVATE_KEY_PATH can be the key itself, rather than a path.

    > NOTE: When this guide says "public key", it's equivelent to "address".

    ```zsh
    export DEPLOYER_PUBLIC_KEY="..."
    export DEPLOYER_PRIVATE_KEY="..."
    export FIREBLOCKS_API_KEY="..."
    export FIREBLOCKS_API_PRIVATE_KEY_PATH="..."
    ```

* Set environment variables for a particular chain.

    Set the chain you are operating on by the key from the `deployment.toml` file.
    An example chain key is "ethereum-sepolia", and you can look at `deployment.toml` for the full list.

    ```zsh
    export CHAIN_KEY="xxx"
    ```

    Now load the chain-specific configs into your shell environment.

    > TODO: Instead of reading these into environment variables, we can have
    > the Forge script directly read them from the TOML file.

    ```zsh
    export RPC_URL=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].rpc-url" deployment_secrets.toml | tee /dev/stderr)
    export ETHERSCAN_URL=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].etherscan-url" deployment.toml | tee /dev/stderr)
    export ETHERSCAN_API_KEY=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].etherscan-api-key" deployment_secrets.toml | tee /dev/stderr)
    export ADMIN_PUBLIC_KEY=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].admin" deployment.toml | tee /dev/stderr)
    ```

    > FUN FACT: Foundry has a config full of information about each chain, mapped from chain ID.
    > It includes the Etherscan compatible API URL, which is how only specifying the API key works.
    > You can find this list in the following source file:
    > https://github.com/alloy-rs/chains/blob/main/src/named.rs

    If the timelock and router contracts are already deployed, you can also load their addresses:

    ```zsh
    export TIMELOCK_CONTROLLER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].timelock-controller" deployment.toml | tee /dev/stderr)
    export VERIFIER_ROUTER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].router" deployment.toml | tee /dev/stderr)
    ```

    > TIP: If you want to see a contract in Etherscan, you can run a command like the example below:
    >
    > ```zsh
    > open ${ETHERSCAN_URL:?}/address/${TIMELOCK_CONTROLLER:?}
    > ```

## Verifier Deployment

Set up your [environment](#environment) for the target chain, as detailed above.

1. Set the verifier selector for the verifier you will be deploying:

    > TIP: One place to find this information is in `./contracts/test/RiscZeroGroth16Verifier.t.sol`

    ```zsh
    export VERIFIER_SELECTOR="0x..."
    ```

2. Dry run deployment of verifier and estop:

    ```zsh
    VERIFIER_ESTOP_OWNER=${ADMIN_PUBLIC_KEY:?} \
    bash contracts/script/manage DeployEstopVerifier
    ```

    > IMPORTANT: Check the logs from this dry run to verify the estop owner is the expected address.
    > It should be equal to the RISC Zero admin address on the given chain.
    > Note that it should not be the TimelockController.
    > Also check the chain ID to ensure you are deploying to the chain you expect.
    > And check the selector to make sure it matches what you expect.

3. Send deployment transactions for verifier and estop by running the command again with `--broadcast`.

    > NOTE: This will result in two transactions sent from the deployer address.
    > If the deployer is configured to use a local private key, as is referenced above, this will not involve Fireblocks.

4. Verify the contracts on Etherscan (equivelent or its equivelent) by running the command again without `--broadcast` and add `--verify`.

5. Add the addresses for the newly deployed contract to the `deployment.toml` file.

    Load the deployed addresses into the environment:

    ```zsh
    export TIMELOCK_CONTROLLER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].timelock-controller" deployment.toml | tee /dev/stderr)
    export VERIFIER_ROUTER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].router" deployment.toml | tee /dev/stderr)
    export VERIFIER_ESTOP=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\") | .estop" deployment.toml | tee /dev/stderr)
    ```

6. Dry run the operation to schedule the operation to add the verifier to the router:

    Fill in the addresses for the relevant chain below.
    `ADMIN_PUBLIC_KEY` should be set to the Fireblocks admin address.

    ```zsh
    bash contracts/script/manage ScheduleAddVerifier -f
    ```

7. Send, through Fireblocks, the transaction for the scheduled update by running the command again with `--broadcast`.

    > IMPORTANT: Running this command will prompt Fireblocks signers for approval.

    > TIP: Foundry and the Fireblocks JSON RPC shim don't quite get along.
    > In order to avoid sending the same transaction for approval twice (or more), use ctrl-c to
    > kill the forge script once you see that the transaction is pending approval in the Fireblocks
    > console.

## Execute the Add Verifier Operation

After the delay on the timelock controller has pass, the operation to add the new verifier to the router can be executed.

Set up your [environment](#environment) for the target chain, as detailed above.
Make sure to set `TIMELOCK_CONTROLLER` and `VERIFIER_ROUTER`.

1. Set the verifier selector and estop address for the verifier:

    > TIP: One place to find this information is in `./contracts/test/RiscZeroGroth16Verifier.t.sol`

    ```zsh
    export VERIFIER_SELECTOR="0x..."
    export VERIFIER_ESTOP=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\") | .estop" deployment.toml | tee /dev/stderr)
    ```

2. Dry the transaction to execute the add verifier operation:

    ```zsh
    bash contracts/script/manage FinishAddVerifier -f
    ```

3. Run the command again with `--broadcast`

## Cancel an Operation

Use the following steps to cancel an operation that is pending on the `TimelockController`.

Set up your [environment](#environment) for the target chain, as detailed above.

1. Identifier the operation ID and set the environment variable.

    > TIP: Once way to get the operation ID is to open the contract in Etherscan and look at the events.
    > On the `CallScheduled` event, the ID is labeled as `[topic1]`.
    >
    > ```zsh
    > open ${ETHERSCAN_URL:?}/address/${TIMELOCK_CONTROLLER:?}#events
    > ```

    ```zsh
    export OPERATION_ID="0x..." \
    ```

2. Dry the transaction to cancel the operation.

    ```zsh
    bash contracts/script/manage CancelOperation
    ```

3. Run the command again with `--broadcast`
