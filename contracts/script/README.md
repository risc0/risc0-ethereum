# Scripts

## Testing with Anvil

Start Anvil:

```console
anvil -a 10 --block-time 1 --host 0.0.0.0 --port 8545
```

Set your public and private key:

```console
export RPC_URL="http://localhost:8545"
export PUBLIC_KEY="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
```

### Deploy the timelocked router

Configure the proposer, executor, and admin:

Deploy the contracts:

```console
MIN_DELAY=1 \
PROPOSER="${PUBLIC_KEY}" \
EXECUTOR="${PUBLIC_KEY}" \
forge script contracts/script/Manage.s.sol:DeployTimelockRouter \
    --slow --broadcast --unlocked \
    --sender ${PUBLIC_KEY} \
    --rpc-url ${RPC_URL}

...

== Logs ==
  minDelay: 1
  proposers: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  executors: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  admin: 0x0000000000000000000000000000000000000000
  Deployed TimelockController to 0x5FbDB2315678afecb367f032d93F642f64180aa3
  Deployed RiscZeroVerifierRouter to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
```

Save the contract addresses:

```console
export TIMELOCK_CONTROLLER="0x5FbDB2315678afecb367f032d93F642f64180aa3"
export VERIFIER_ROUTER="0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
```

Test the deployment:

```console
cast call --rpc-url ${RPC_URL} \
    ${TIMELOCK_CONTROLLER} \
    'getMinDelay()(uint256)'
1

cast call --rpc-url ${RPC_URL} \
    ${VERIFIER_ROUTER} \
    'owner()(address)'
0x5FbDB2315678afecb367f032d93F642f64180aa3
```

### Deploy a verifier

Deploy the contracts:

```console
SELECTOR=0xaabbccdd \
SCHEDULE_DELAY=1 \
VERIFIER_ESTOP_OWNER=${PUBLIC_KEY} \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER} \
VERIFIER_ROUTER=${VERIFIER_ROUTER} \
forge script contracts/script/Manage.s.sol:DeployEstopVerifier \
    --slow --broadcast --unlocked \
    --sender ${PUBLIC_KEY} \
    --rpc-url ${RPC_URL}

...

== Logs ==
  selector:
  0xaabbccdd
  scheduleDelay: 1
  verifierEstopOwner: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  Using RiscZeroVerifierRouter at address 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  Deployed IRiscZeroVerifier to 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
  Deployed RiscZeroVerifierEmergencyStop to 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
```

Save the e-stop contract address:

```console
export VERIFIER_ESTOP="0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
```

Test the deployment:

```console
cast call --rpc-url ${RPC_URL} \
    ${VERIFIER_ESTOP} \
    'owner()(address)'
0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

### Finish adding verifier to router

Tell the TimelockController to execute the action:

```console
SELECTOR=0xaabbccdd \
TIMELOCK_CONTROLLER=${TIMELOCK_CONTROLLER} \
VERIFIER_ROUTER=${VERIFIER_ROUTER} \
VERIFIER_ESTOP=${VERIFIER_ESTOP} \
forge script contracts/script/Manage.s.sol:FinishDeployEstopVerifier \
    --slow --broadcast --unlocked \
    --sender ${PUBLIC_KEY} \
    --rpc-url ${RPC_URL}

...

== Logs ==
  selector:
  0xaabbccdd
  Using TimelockController at address 0x5FbDB2315678afecb367f032d93F642f64180aa3
  Using RiscZeroVerifierRouter at address 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  Using RiscZeroVerifierEmergencyStop at address 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
```

Test the deployment:

```console
cast call --rpc-url ${RPC_URL} \
    ${VERIFIER_ROUTER} \
    'getVerifier(bytes4)(address)' 0xaabbccdd
0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9
```
