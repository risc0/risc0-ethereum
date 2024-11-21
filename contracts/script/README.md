# Contract Operations Guide

An operations guide for the RISC Zero Ethereum contracts.

> [!NOTE]
> All the commands in this guide assume your current working directory is the root of the repo.

## Dependencies

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

> [!NOTE]
> Running the `manage` commands will run in simulation mode (i.e. will not send transactions) unless the `--broadcast` flag is passed.

Commands in this guide use `yq` to parse the TOML config files.

You can install `yq` by following the [direction on GitHub][yq-install], or using `go install`.

```bash
go install github.com/mikefarah/yq/v4@latest
```

## Configuration

Configurations and deployment state information is stored in `deployment.toml`.
It contains information about each chain (e.g. name, ID, Etherscan URL), and addresses for the timelock, router, and verifier contracts on each chain.

Accompanying the `deployment.toml` file is a `deployment_secrets.toml` file with the following schema.
It is used to store somewhat sensitive API keys for RPC services and Etherscan.
Note that it does not contain private keys or API keys for Fireblocks.
It should never be committed to `git`, and the API keys should be rotated if this occurs.

```toml
[chains.$CHAIN_KEY]
rpc-url = "..."
etherscan-api-key = "..."
```

## Environment

### Anvil

In development and to test the operations process, you can use Anvil.

Start Anvil:

```bash
anvil -a 10 --block-time 1 --host 0.0.0.0 --port 8545
```

Set your RPC URL, as well as your public and private key:

```bash
export RPC_URL="http://localhost:8545"
export DEPLOYER_PUBLIC_KEY="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
export DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
```

### Public Networks (Testnet or Mainnet)

Set the chain you are operating on by the key from the `deployment.toml` file.
An example chain key is "ethereum-sepolia", and you can look at `deployment.toml` for the full list.

> TODO: Instead of reading these into environment variables, we can have the Forge script directly read them from the TOML file.

```zsh
export CHAIN_KEY="xxx-testnet"
```

Set your RPC URL, public and private key, and Etherscan API key:

```bash
export RPC_URL=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].rpc-url" contracts/deployment_secrets.toml | tee /dev/stderr)
export ETHERSCAN_URL=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].etherscan-url" contracts/deployment.toml | tee /dev/stderr)
export ETHERSCAN_API_KEY=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].etherscan-api-key" contracts/deployment_secrets.toml | tee /dev/stderr)
export ADMIN_PUBLIC_KEY=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].admin" contracts/deployment.toml | tee /dev/stderr)
```

> [!TIP]
> Foundry has a [config full of information about each chain][alloy-chains], mapped from chain ID.
> It includes the Etherscan compatible API URL, which is how only specifying the API key works.
> You can find this list in the following source file:

Example RPC URLs:

* `https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY`
* `https://sepolia.infura.io/v3/YOUR_API_KEY`

If the timelock and router contracts are already deployed, you can also load their addresses:

```zsh
export TIMELOCK_CONTROLLER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].timelock-controller" contracts/deployment.toml | tee /dev/stderr)
export VERIFIER_ROUTER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].router" contracts/deployment.toml | tee /dev/stderr)
```

> TIP: If you want to see a contract in Etherscan, you can run a command like the example below:
>
> ```zsh
> open ${ETHERSCAN_URL:?}/address/${TIMELOCK_CONTROLLER:?}
> ```

### Fireblocks

Requires the [Fireblocks integration for Foundry](https://developers.fireblocks.com/docs/ethereum-smart-contract-development#using-foundry).

Also requires that you have a [Fireblocks API account](https://developers.fireblocks.com/docs/quickstart).

Set your public key, your Etherscan API key, and the necessary parameters for Fireblocks:

> [!NOTE]
> Fireblocks only supports RSA for API request signing.
> `FIREBLOCKS_API_PRIVATE_KEY_PATH` can be the key itself, rather than a path.

> [!NOTE]
> When this guide says "public key", it's equivalent to "address".

```bash
export FIREBLOCKS_API_KEY="..."
export FIREBLOCKS_API_PRIVATE_KEY_PATH="..."

# IF YOU ARE IN A SANDBOX ENVIRONMENT, be sure to also set this:
export FIREBLOCKS_API_BASE_URL="https://sandbox-api.fireblocks.io"
```

Then, in the instructions below, pass the `--fireblocks` (`-f`) flag to the `manage` script.

> [!NOTE]
> Your Fireblocks API user will need to have "Editor" permissions (i.e., ability to propose transactions for signing, but not necessarily the ability to sign transactions). You will also need a Transaction Authorization Policy (TAP) that specifies who the signers are for transactions initiated by your API user, and this policy will need to permit contract creation as well as contract calls.

> [!NOTE]
> Before you approve any contract-call transactions, be sure you understand what the call does! When in doubt, use [Etherscan](https://etherscan.io/) to lookup the function selector, together with a [calldata decoder](https://openchain.xyz/tools/abi) ([alternative](https://calldata.swiss-knife.xyz/decoder)) to decode the call's arguments.

> [!TIP]
> Foundry and the Fireblocks JSON RPC shim don't quite get along.
> In order to avoid sending the same transaction for approval twice (or more), use ctrl-c to
> kill the forge script once you see that the transaction is pending approval in the Fireblocks
> console.

## Deploy the timelocked router

1. Dry run the contract deployment:

    > [!IMPORTANT]
    > Adjust the `MIN_DELAY` to a value appropriate for the environment (e.g. 1 second for testnet and 604800 seconds (7 days) for mainnet).

    ```bash
    MIN_DELAY=1 \
    PROPOSER="${ADMIN_PUBLIC_KEY:?}" \
    EXECUTOR="${ADMIN_PUBLIC_KEY:?}" \
    bash contracts/script/manage DeployTimelockRouter

    ...

    == Logs ==
      minDelay: 1
      proposers: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
      executors: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
      admin: 0x0000000000000000000000000000000000000000
      Deployed TimelockController to 0x5FbDB2315678afecb367f032d93F642f64180aa3
      Deployed RiscZeroVerifierRouter to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
    ```

2. Run the command again with `--broadcast`.

    This will result in two transactions sent from the deployer address.

3. Verify the contracts on Etherscan (or its equivalent) by running the command again without `--broadcast` and add `--verify`.

4. Save the contract addresses to `deployment.toml`.

    Load the addresses into your environment.

    ```bash
    export TIMELOCK_CONTROLLER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].timelock-controller" contracts/deployment.toml | tee /dev/stderr)
    export VERIFIER_ROUTER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].router" contracts/deployment.toml | tee /dev/stderr)
    ```

5. Test the deployment:

    ```bash
    cast call --rpc-url ${RPC_URL:?} \
        ${TIMELOCK_CONTROLLER:?} \
        'getMinDelay()(uint256)'
    1

    cast call --rpc-url ${RPC_URL:?} \
        ${VERIFIER_ROUTER:?} \
        'owner()(address)'
    0x5FbDB2315678afecb367f032d93F642f64180aa3
    ```

## Deploy a verifier with emergency stop mechanism

This is a two-step process, guarded by the `TimelockController`.

### Deploy the verifier

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

    > [!IMPORTANT]
    > Check the logs from this dry run to verify the estop owner is the expected address.
    > It should be equal to the RISC Zero admin address on the given chain.
    > Note that it should not be the `TimelockController`.
    > Also check the chain ID to ensure you are deploying to the chain you expect.
    > And check the selector to make sure it matches what you expect.

3. Send deployment transactions for verifier and estop by running the command again with `--broadcast`.

    This will result in two transactions sent from the deployer address.

    > [!NOTE]
    > When using Fireblocks, sending a transaction to a particular address may require allow-listing it.
    > In order to ensure that estop operations are possible, make sure to allow-list the new estop contract.

4. Verify the contracts on Etherscan (or its equivalent) by running the command again without `--broadcast` and add `--verify`.

5. Add the addresses for the newly deployed contract to the `deployment.toml` file.

    Load the deployed addresses into the environment:

    ```zsh
    export TIMELOCK_CONTROLLER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].timelock-controller" contracts/deployment.toml | tee /dev/stderr)
    export VERIFIER_ROUTER=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].router" contracts/deployment.toml | tee /dev/stderr)
    export VERIFIER_ESTOP=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\") | .estop" contracts/deployment.toml | tee /dev/stderr)
    ```

6. Test the deployment.

    ```console
    cast call --rpc-url ${RPC_URL:?} \
        ${VERIFIER_ESTOP:?} \
        'paused()(bool)'
    false

    cast call --rpc-url ${RPC_URL:?} \
        ${VERIFIER_ESTOP:?} \
        'owner()(address)'
    0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    ```

7. Dry run the operation to schedule the operation to add the verifier to the router.

    Fill in the addresses for the relevant chain below.
    `ADMIN_PUBLIC_KEY` should be set to the Fireblocks admin address.

    ```zsh
    bash contracts/script/manage ScheduleAddVerifier
    ```

8. Send the transaction for the scheduled update by running the command again with `--broadcast`.

    This will send one transaction from the admin address.

    > [!IMPORTANT]
    > If the admin address is in Fireblocks, this will prompt the admins for approval.

### Finish the update

After the delay on the timelock controller has pass, the operation to add the new verifier to the router can be executed.

Make sure to set `TIMELOCK_CONTROLLER` and `VERIFIER_ROUTER`.

1. Set the verifier selector and estop address for the verifier:

    > TIP: One place to find this information is in `./contracts/test/RiscZeroGroth16Verifier.t.sol`

    ```zsh
    export VERIFIER_SELECTOR="0x..."
    export VERIFIER_ESTOP=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\") | .estop" contracts/deployment.toml | tee /dev/stderr)
    ```

2. Dry the transaction to execute the add verifier operation:

    ```zsh
    bash contracts/script/manage FinishAddVerifier
    ```

3. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

4. Test the deployment.

    ```bash
    cast call --rpc-url ${RPC_URL:?} \
        ${VERIFIER_ROUTER:?} \
        'getVerifier(bytes4)(address)' ${VERIFIER_SELECTOR:?}
    0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
    ```

## Remove a verifier

This is a two-step process, guarded by the `TimelockController`.

### Schedule the update

1. Set the verifier selector and estop address for the verifier:

    > TIP: One place to find this information is in `./contracts/test/RiscZeroGroth16Verifier.t.sol`

    ```zsh
    export VERIFIER_SELECTOR="0x..."
    ```

2. Dry the transaction to schedule the remove verifier operation:

    ```bash
    bash contracts/script/manage ScheduleRemoveVerifier
    ```

3. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

### Finish the update

1. Set the verifier selector and estop address for the verifier:

    > TIP: One place to find this information is in `./contracts/test/RiscZeroGroth16Verifier.t.sol`

    ```zsh
    export VERIFIER_SELECTOR="0x..."
    ```

2. Dry the transaction to execute the remove verifier operation:

    ```bash
    bash contracts/script/manage FinishRemoveVerifier
    ```

3. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

4. Confirm it was removed.

    ```bash
    cast call --rpc-url ${RPC_URL:?} \
        ${VERIFIER_ROUTER:?} \
        'getVerifier(bytes4)(address)' ${VERIFIER_SELECTOR:?}
    Error: ... execution reverted
    ```

## Update the TimelockController minimum delay

This is a two-step process, guarded by the `TimelockController`.

### Schedule the update

1. Dry run the transaction:

    ```bash
    MIN_DELAY=10 \
    bash contracts/script/manage ScheduleUpdateDelay
    ```

2. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

### Finish the update

Execute the action:

1. Dry run the transaction:

    ```bash
    MIN_DELAY=10 \
    bash contracts/script/manage FinishUpdateDelay
    ```

2. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

3. Confirm the update.

    ```bash
    cast call --rpc-url ${RPC_URL:?} \
        ${TIMELOCK_CONTROLLER:?} \
        'getMinDelay()(uint256)'
    10
    ```

## Cancel a scheduled timelock operation

Use the following steps to cancel an operation that is pending on the `TimelockController`.

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
    bash contracts/script/manage CancelOperation -f
    ```

3. Run the command again with `--broadcast`

## Grant access to the TimelockController

This is a two-step process, guarded by the `TimelockController`.

Three roles are supported:

* `proposer`
* `executor`
* `canceller`

### Schedule the update

1. Dry run the transaction:

    ```bash
    ROLE="executor" \
    ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
    bash contracts/script/manage ScheduleGrantRole
    ```

2. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

### Finish the update

1. Dry run the transaction:

    ```bash
    ROLE="executor" \
    ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
    bash contracts/script/manage FinishGrantRole
    ```

2. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

3. Confirm the update:

    ```bash
    # Query the role code.
    cast call --rpc-url ${RPC_URL:?} \
        ${TIMELOCK_CONTROLLER:?} \
        'EXECUTOR_ROLE()(bytes32)'
    0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63

    # Check that the account now has that role.
    cast call --rpc-url ${RPC_URL:?} \
        ${TIMELOCK_CONTROLLER:?} \
        'hasRole(bytes32, address)(bool)' \
        0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63 \
        0x00000000000000aabbccddeeff00000000000000
    true
    ```

## Revoke access to the TimelockController

This is a two-step process, guarded by the `TimelockController`.

Three roles are supported:

* `proposer`
* `executor`
* `canceller`

### Schedule the update

1. Dry run the transaction:

    ```bash
    ROLE="executor" \
    ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
    bash contracts/script/manage ScheduleRevokeRole
    ```

2. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

Confirm the role code:

```bash
cast call --rpc-url ${RPC_URL:?} \
    ${TIMELOCK_CONTROLLER:?} \
    'EXECUTOR_ROLE()(bytes32)'
0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
```

### Finish the update

1. Dry run the transaction:

    ```bash
    ROLE="executor" \
    ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
    bash contracts/script/manage FinishRevokeRole
    ```

2. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

3. Confirm the update:

    ```bash
    # Query the role code.
    cast call --rpc-url ${RPC_URL:?} \
        ${TIMELOCK_CONTROLLER:?} \
        'EXECUTOR_ROLE()(bytes32)'
    0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63

    # Check that the account no longer has that role.
    cast call --rpc-url ${RPC_URL:?} \
        ${TIMELOCK_CONTROLLER:?} \
        'hasRole(bytes32, address)(bool)' \
        0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63 \
        0x00000000000000aabbccddeeff00000000000000
    false
    ```

## Renounce access to the TimelockController

If your private key is compromised, you can renounce your role(s) without waiting for the time delay. Repeat this action for any of the roles you might have, such as:

* proposer
* executor
* canceller

> ![WARNING]
> Renouncing authorization on the timelock controller may make permanently inoperable.

1. Dry run the transaction:

    ```bash
    RENOUNCE_ROLE="executor" \
    RENOUNCE_ADDRESS="0x00000000000000aabbccddeeff00000000000000" \
    bash contracts/script/manage RenounceRole
    ```

2. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

3. Confirm:

    ```bash
    cast call --rpc-url ${RPC_URL:?} \
        ${TIMELOCK_CONTROLLER:?} \
        'hasRole(bytes32, address)(bool)' \
        0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63 \
        ${RENOUNCE_ADDRESS:?}
    false
    ```

## Activate the emergency stop

Activate the emergency stop:

> ![WARNING]
> Activating the emergency stop will make that verifier permanently inoperable.

1. Set the verifier selector and estop address for the verifier:

    > TIP: One place to find this information is in `./contracts/test/RiscZeroGroth16Verifier.t.sol`

    ```zsh
    export VERIFIER_SELECTOR="0x..."
    export VERIFIER_ESTOP=$(yq eval -e ".chains[\"${CHAIN_KEY:?}\"].verifiers[] | select(.selector == \"${VERIFIER_SELECTOR:?}\") | .estop" contracts/deployment.toml | tee /dev/stderr)
    ```

2. Dry run the transaction

    ```bash
    VERIFIER_ESTOP=${VERIFIER_ESTOP:?} \
    bash contracts/script/manage ActivateEstop
    ```

3. Run the command again with `--broadcast`

    This will send one transaction from the admin address.

4. Test the activation:

    ```bash
    cast call --rpc-url ${RPC_URL:?} \
        ${VERIFIER_ESTOP:?} \
        'paused()(bool)'
    true
    ```

[yq-install]: https://github.com/mikefarah/yq?tab=readme-ov-file#install
[alloy-chains]: https://github.com/alloy-rs/chains/blob/main/src/named.rs
