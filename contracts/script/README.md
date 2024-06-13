# Scripts

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

> [!NOTE]
> Running the `manage` commands will run in simulation mode (i.e. will not send transactions) unless the `--broadcast` flag is passed.

## Setup your environment

### Anvil

Start Anvil:

```console
anvil -a 10 --block-time 1 --host 0.0.0.0 --port 8545
```

Set your RPC URL, as well as your public and private key:

```console
export RPC_URL="http://localhost:8545"
export PUBLIC_KEY="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
```

### Sepolia or Mainnet

Set your RPC URL, public and private key, and Etherscan API key:

```console
export RPC_URL="..."
export PUBLIC_KEY="..."
export PRIVATE_KEY="..."
export ETHERSCAN_API_KEY="..."
export FORGE_DEPLOY_FLAGS="--verify"
```

Example RPC URLs:

* Sepolia:
  * https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
  * https://sepolia.infura.io/v3/YOUR_API_KEY
* Mainnet:
  * https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
  * https://mainnet.infura.io/v3/YOUR_API_KEY

### Fireblocks

Requires the [Fireblocks integration for Foundry](https://developers.fireblocks.com/docs/ethereum-smart-contract-development#using-foundry).

Also requires that you have a [Fireblocks API account](https://developers.fireblocks.com/docs/quickstart).

Set your public key, your Etherscan API key, and the necessary parameters for Fireblocks:

```console
export RPC_URL="..."
export PUBLIC_KEY="..."
export ETHERSCAN_API_KEY="..."
export FORGE_DEPLOY_FLAGS="--verify"
export FIREBLOCKS_API_KEY="..."
export FIREBLOCKS_API_PRIVATE_KEY_PATH="/path/to/secret.key"

# IF YOU ARE IN A SANDBOX ENVIRONMENT, be sure to also set this:
export FIREBLOCKS_API_BASE_URL="https://sandbox-api.fireblocks.io"
```

Then, in the instructions below, pass the `--fireblocks` flag to the `manage` script.

> [!NOTE]
> Your Fireblocks API user will need to have "Editor" permissions (i.e., ability to propose transactions for signing, but not necessarily the ability to sign transactions). You will also need a Transaction Authorization Policy (TAP) that specifies who the signers are for transactions initiated by your API user, and this policy will need to permit contract creation as well as contract calls.

> [!NOTE]
> Before you approve any contract-call transactions, be sure you understand what the call does! When in doubt, use [Etherscan](https://etherscan.io/) to lookup the function selector, together with a [calldata decoder](https://openchain.xyz/tools/abi) ([alternative](https://calldata.swiss-knife.xyz/decoder)) to decode the call's arguments.

## Deploy the timelocked router

Deploy the contracts:

```console
MIN_DELAY=1 \
PROPOSER="${PUBLIC_KEY:?}" \
EXECUTOR="${PUBLIC_KEY:?}" \
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

Look at the command logs and save the contract addresses:

```console
export TIMELOCK_CONTROLLER="0x5FbDB2315678afecb367f032d93F642f64180aa3"
export VERIFIER_ROUTER="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
```

Test the deployment:

```console
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

This is a 3-step process, guarded by the `TimelockController`.

### Deploy the verifier

Deploy the contracts:

```console
VERIFIER_ESTOP_OWNER=${PUBLIC_KEY:?} \
bash contracts/script/manage DeployEstopVerifier

...

== Logs ==
  verifierEstopOwner: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  Deployed RiscZeroGroth16Verifier to 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
  Deployed RiscZeroVerifierEmergencyStop to 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
```

Look at the command logs and save the e-stop contract address:

```console
export VERIFIER_ESTOP="0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
```

Test the deployment:

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

### Schedule the update

Schedule the action:

```console
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
VERIFIER_ROUTER=${VERIFIER_ROUTER:?} \
VERIFIER_ESTOP=${VERIFIER_ESTOP:?} \
bash contracts/script/manage ScheduleAddVerifier

...

== Logs ==
  Using RiscZeroVerifierEmergencyStop at address 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
  Using RiscZeroGroth16Verifier at address 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
  selector:
  0x310fe598
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  scheduleDelay: 1
  Using RiscZeroVerifierRouter at address 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  Simulating call to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  0xd0a6af30310fe59800000000000000000000000000000000000000000000000000000000000000000000000000000000cf7ed3acca5a467e9e704c703e8d87f634fb0fc9
  Simulation successful
```

### Finish the update

Execute the action:

```console
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
VERIFIER_ROUTER=${VERIFIER_ROUTER:?} \
VERIFIER_ESTOP=${VERIFIER_ESTOP:?} \
bash contracts/script/manage FinishAddVerifier

...

== Logs ==
  Using RiscZeroVerifierEmergencyStop at address 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
  Using RiscZeroGroth16Verifier at address 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
  selector:
  0x310fe598
  Using RiscZeroVerifierRouter at address 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

Test the deployment:

```console
export VERIFIER="$(cast call --rpc-url ${RPC_URL:?} ${VERIFIER_ESTOP:?} 'verifier()(address)')"
export SELECTOR="$(cast call --rpc-url ${RPC_URL:?} ${VERIFIER:?} 'SELECTOR()(bytes4)' | head -c 10)"
```

```console
cast call --rpc-url ${RPC_URL:?} \
    ${VERIFIER_ROUTER:?} \
    'getVerifier(bytes4)(address)' ${SELECTOR:?}
0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
```

## Remove a verifier

This is a two-step process, guarded by the `TimelockController`.

### Schedule the update

Schedule the action:

```console
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
VERIFIER_ROUTER=${VERIFIER_ROUTER:?} \
bash contracts/script/manage ScheduleRemoveVerifier

...

== Logs ==
  selector:
  0x310fe598
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  scheduleDelay: 1
  Using RiscZeroVerifierRouter at address 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  Simulating call to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  0x93d237f6310fe59800000000000000000000000000000000000000000000000000000000
  Simulation successful
```

### Finish the update

Execute the action:

```console
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
VERIFIER_ROUTER=${VERIFIER_ROUTER:?} \
bash contracts/script/manage FinishRemoveVerifier

...

== Logs ==
  selector:
  0x310fe598
  Using RiscZeroVerifierRouter at address 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

Confirm it was removed:

```console
cast call --rpc-url ${RPC_URL:?} \
    ${VERIFIER_ROUTER:?} \
    'getVerifier(bytes4)(address)' ${SELECTOR:?}
Error: ... execution reverted
```

## Update the TimelockController minimum delay

This is a two-step process, guarded by the `TimelockController`.

### Schedule the update

Schedule the action:

```console
MIN_DELAY=10 \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
bash contracts/script/manage ScheduleUpdateDelay

...

== Logs ==
  minDelay: 10
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  scheduleDelay: 1
  Simulating call to 0x5FbDB2315678afecb367f032d93F642f64180aa3
  0x64d62353000000000000000000000000000000000000000000000000000000000000000a
  Simulation successful
```

### Finish the update

Execute the action:

```console
MIN_DELAY=10 \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
bash contracts/script/manage FinishUpdateDelay

...

== Logs ==
  minDelay: 10
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

Confirm the update:

```console
cast call --rpc-url ${RPC_URL:?} \
    ${TIMELOCK_CONTROLLER:?} \
    'getMinDelay()(uint256)'
10
```

## Grant access to the TimelockController

This is a two-step process, guarded by the `TimelockController`.

Three roles are supported:

* `proposer`
* `executor`
* `canceller`

### Schedule the update

Schedule the action:

```console
ROLE="executor" \
ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
bash contracts/script/manage ScheduleGrantRole

...

== Logs ==
  roleStr: executor
  account: 0x00000000000000AABBCcdDEefF00000000000000
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  role: 
  0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
  scheduleDelay: 10
  Simulating call to 0x5FbDB2315678afecb367f032d93F642f64180aa3
  0x2f2ff15dd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e6300000000000000000000000000000000000000aabbccddeeff00000000000000
  Simulation successful
```

Confirm the role code:

```console
cast call --rpc-url ${RPC_URL:?} \
    ${TIMELOCK_CONTROLLER:?} \
    'EXECUTOR_ROLE()(bytes32)'
0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
```

### Finish the update

Schedule the action:

```console
ROLE="executor" \
ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
bash contracts/script/manage FinishGrantRole

...

== Logs ==
  roleStr: executor
  account: 0x00000000000000AABBCcdDEefF00000000000000
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  role: 
  0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
```

Confirm the update:

```console
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

Schedule the action:

```console
ROLE="executor" \
ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
bash contracts/script/manage ScheduleRevokeRole

...

== Logs ==
  roleStr: executor
  account: 0x00000000000000AABBCcdDEefF00000000000000
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  role: 
  0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
  scheduleDelay: 10
  Simulating call to 0x5FbDB2315678afecb367f032d93F642f64180aa3
  0xd547741fd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e6300000000000000000000000000000000000000aabbccddeeff00000000000000
  Simulation successful
```

Confirm the role code:

```console
cast call --rpc-url ${RPC_URL:?} \
    ${TIMELOCK_CONTROLLER:?} \
    'EXECUTOR_ROLE()(bytes32)'
0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
```

### Finish the update

Schedule the action:

```console
ROLE="executor" \
ACCOUNT="0x00000000000000aabbccddeeff00000000000000" \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
bash contracts/script/manage FinishRevokeRole

...

== Logs ==
  roleStr: executor
  account: 0x00000000000000AABBCcdDEefF00000000000000
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  role: 
  0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
```

Confirm the update:

```console
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

```console
ROLE="executor" \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER:?} \
bash contracts/script/manage RenounceRole

...

== Logs ==
  roleStr: executor
  msg.sender: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  role: 
  0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63
```

Confirm:

```console
cast call --rpc-url ${RPC_URL:?} \
    ${TIMELOCK_CONTROLLER:?} \
    'hasRole(bytes32, address)(bool)' \
    0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63 \
    ${PUBLIC_KEY:?}
false
```

## Activate the emergency stop

Activate the emergency stop:

```console
VERIFIER_ESTOP=${VERIFIER_ESTOP:?} \
bash contracts/script/manage ActivateEstop

...

== Logs ==
  Using RiscZeroVerifierEmergencyStop at address 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
```

Test the activation:

```console
cast call --rpc-url ${RPC_URL:?} \
    ${VERIFIER_ESTOP:?} \
    'paused()(bool)'
true
```
