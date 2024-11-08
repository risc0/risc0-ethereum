# RISC Zero View Call Proofs ERC20 Example Ethereum Deployment Guide

> **Note: This software is not production ready. Do not use in production.**

Welcome to the [RISC Zero] View Call Proofs ERC20 Example Ethereum Deployment guide!

You can either:

- [Deploy to a local network]
- [Deploy to a testnet]

## Deploy on a local devnet

You can deploy your contracts and run an end-to-end test or demo as follows:

1. Start a local testnet with `anvil` by running:

    ```bash
    anvil
    ```

   Once anvil is started, keep it running in the terminal, and switch to a new terminal.

2. Set your environment variables:
    > ***Note:*** *This requires having access to a Bonsai API Key. To request an API key [complete the form here](https://bonsai.xyz/apply).*
    >
    > Alternatively you can generate your proofs locally, assuming you have a machine with an x86 architecture and [Docker] installed. In this case do not export Bonsai related env variables.

    ```bash
    # Anvil sets up a number of default wallets, and this private key is one of them.
    export ETH_WALLET_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    export BONSAI_API_KEY="YOUR_API_KEY" # see form linked in the previous section
    export BONSAI_API_URL="BONSAI_API_URL" # provided with your api key
    ```
3. Build the Project:
    ```bash
    cargo build
    ```
    
4. Deploy the Counter contract. During creation, the Counter gets linked with an ERC20 token. To also deploy such a new token, you need to specify any `TOKEN_OWNER` address which will get funded with Toyken ERC20 tokens, for example the address of the private key:
    ```bash
    export TOKEN_OWNER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    ```
    Then, deploy the contracts running the following script:
    ```bash
    forge script --rpc-url http://localhost:8545 --broadcast DeployCounter
    ```
    This command should output something similar to:

    ```bash
    ...
    == Logs ==
    Deployed ERC20 TOYKEN to 0x5FbDB2315678afecb367f032d93F642f64180aa3
    Deployed RiscZeroGroth16Verifier to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
    Deployed Counter to 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
    ...
    ```
    Save the `ERC20 Toyken` contract address to an env variable:
    ```bash
    export TOYKEN_ADDRESS=#COPY ERC20 TOYKEN ADDRESS FROM DEPLOY LOGS
    ```

    > You can also use the following command to set the contract address if you have [`jq`][jq] installed:
    >
    > ```bash
    > export TOYKEN_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "ERC20FixedSupply") | .contractAddress' ./broadcast/DeployCounter.s.sol/31337/run-latest.json)
    > ```

    Save the `Counter` contract address to an env variable:

    ```bash
    export COUNTER_ADDRESS=#COPY COUNTER ADDRESS FROM DEPLOY LOGS
    ```
    > You can also use the following command to set the contract address if you have [`jq`][jq] installed:
    >
    > ```bash
    > export COUNTER_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/DeployCounter.s.sol/31337/run-latest.json)
    > ```

### Interact with your local deployment

1. Query the state:

    ```bash
    cast call --rpc-url http://localhost:8545 $COUNTER_ADDRESS 'get()(uint256)'
    ```

2. Publish a new state

    ```bash
    RUST_LOG=info cargo run --bin publisher -- \
        --eth-wallet-private-key=$ETH_WALLET_PRIVATE_KEY \
        --eth-rpc-url=http://localhost:8545 \
        --counter-address=$COUNTER_ADDRESS \
        --token-contract=$TOYKEN_ADDRESS \
        --account=$TOKEN_OWNER
    ```

3. Query the state again to see the change:

    ```bash
    cast call --rpc-url http://localhost:8545 $COUNTER_ADDRESS 'get()(uint256)'
    ```

## Deploy your project on a public network

You can deploy the Counter contract on any Ethereum network such as `Sepolia` (in this example we will be using [PublicNode](https://ethereum.publicnode.com/)) and run an end-to-end test or demo as follows:
> ***Note***: we'll be using an existing ERC20 contract for this example, specifically the USDT ERC20 contract deployed on Sepolia at address [0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0].

1. Get access to Bonsai and an Ethereum node running on a given testnet, e.g., Sepolia and export the following environment variables:
    > ***Note:*** *This requires having access to a Bonsai API Key. To request an API key [complete the form here](https://bonsai.xyz/apply).*
    >
    > Alternatively you can generate your proofs locally, assuming you have a machine with an x86 architecture and [Docker] installed. In this case do not export Bonsai related env variables.

    ```bash
    export BONSAI_API_KEY="YOUR_API_KEY" # see form linked in the previous section
    export BONSAI_API_URL="BONSAI_API_URL" # provided with your api key
    export ETH_WALLET_PRIVATE_KEY="YOUR_WALLET_PRIVATE_KEY" # the private hex-encoded key of your Sepolia testnet wallet
    export TOKEN_CONTRACT=0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0 # Sepolia USDT
    ```

2. Build the project:
    ```bash
    cargo build
    ```

3. Deploy the Counter contract by running:

    ```bash
    forge script --rpc-url https://ethereum-sepolia-rpc.publicnode.com --broadcast DeployCounter
    ```

     This command should output something similar to:

    ```bash
    ...
    == Logs ==
    Using ERC20 USDT at 0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0
    Deployed RiscZeroGroth16Verifier to 0x5a1677454B5530a15536EF662C6b27b14F699aBd
    Deployed Counter to 0xb0827e4F251d29685170837C2C0eE204Dfef522c
    ...
    ```

    Save the `Counter` contract address to an env variable:

    ```bash
    export COUNTER_ADDRESS=#COPY COUNTER ADDRESS FROM DEPLOY LOGS
    ```

### Interact with your testnet deployment

1. Query the state. It should return `0` for a newly deployed Counter contract:

    ```bash
    cast call --rpc-url https://ethereum-sepolia-rpc.publicnode.com $COUNTER_ADDRESS 'get()(uint256)'
    ```

2. Publish a new state

    ```bash
    RUST_LOG=info cargo run --bin publisher -- \
        --eth-wallet-private-key=$ETH_WALLET_PRIVATE_KEY \
        --eth-rpc-url=https://ethereum-sepolia-rpc.publicnode.com \
        --counter-address=$COUNTER_ADDRESS \
        --token-contract=$TOKEN_CONTRACT \
        --account=0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4
    ```

3. Query the state again to see the change:

    ```bash
    cast call --rpc-url https://ethereum-sepolia-rpc.publicnode.com $COUNTER_ADDRESS 'get()(uint256)'
    ```

[Deploy to a testnet]: #deploy-your-project-on-a-testnet
[Deploy to a local network]: #deploy-on-a-local-network
[RISC Zero]: https://www.risczero.com/
[Node.js]: https://nodejs.org/
[jq]: https://jqlang.github.io/jq/
[methods]: ./methods/
[tested]: ./README.md#run-the-tests
[0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0]: https://sepolia.etherscan.io/address/0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0#code
[methods/guest/src/bin/balance_of.rs]: ./methods/guest/src/bin/balance_of.rs
[apps/src/bin/publisher.rs]: ./apps/src/bin/publisher.rs
[Docker]: https://docs.docker.com/get-docker/
