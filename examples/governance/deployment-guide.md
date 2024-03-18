# RISC Zero Ethereum Deployment Guide

> **Note: This software is not production ready. Do not use in production.**

Welcome to the [RISC Zero] Ethereum Deployment guide!

Once you've written your [contracts] and your [methods], and [tested] your program, you're ready to deploy your contract.

You can either:

- [Deploy your project to a local network]
- [Deploy to a testnet]

## Deploy your project on a local network

You can deploy your contracts and run an end-to-end test or demo as follows:

1. Start a local testnet with `anvil` by running:

    ```bash
    anvil
    ```

    Once anvil is started, keep it running in the terminal, and switch to a new terminal.

2. Set your environment variables:
    > ***Note:*** *This requires having access to a Bonsai API Key. To request an API key [complete the form here](https://bonsai.xyz/apply).*

    ```bash
    # Anvil sets up a number of default wallets, and this private key is one of them.
    export ETH_WALLET_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    export BONSAI_API_KEY="YOUR_API_KEY" # see form linked in the previous section
    export BONSAI_API_URL="BONSAI_API_URL" # provided with your api key
    ```

3. Build your project:

    ```bash
    cargo build
    ```

4. Deploy your contract by running:

    ```bash
    forge script --rpc-url http://localhost:8545 --broadcast script/Deploy.s.sol
    ```

    This command should output something similar to:

    ```bash
    ...
    == Logs ==
    Deployed RiscZeroGroth16Verifier to 0x5FbDB2315678afecb367f032d93F642f64180aa3
    Deployed EvenNumber to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
    ...
    ```

    Save the `EvenNumber` contract address to an env variable:

    ```bash
    export EVEN_NUMBER_ADDRESS=#COPY EVEN NUMBER ADDRESS FROM DEPLOY LOGS
    ```

    > You can also use the following command to set the contract address if you have [`jq`][jq] installed:
    >
    > ```bash
    > export EVEN_NUMBER_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "EvenNumber") | .contractAddress' ./broadcast/Deploy.s.sol/31337/run-latest.json)
    > ```

### Interact with your local deployment

1. Query the state:

    ```bash
    cast call --rpc-url http://localhost:8545 ${EVEN_NUMBER_ADDRESS:?} 'get()(uint256)'
    ```

2. Publish a new state

    ```bash
    cargo run --bin publisher -- \
        --chain-id=31337 \
        --rpc-url=http://localhost:8545 \
        --contract=${EVEN_NUMBER_ADDRESS:?} \
        --input=12345678
    ```

3. Query the state again to see the change:

    ```bash
    cast call --rpc-url http://localhost:8545 ${EVEN_NUMBER_ADDRESS:?} 'get()(uint256)'
    ```

## Deploy your project on a testnet

You can deploy your contracts on a testnet such as `Sepolia` and run an end-to-end test or demo as follows:

1. Get access to Bonsai and an Ethereum node running on a given testnet, e.g., Sepolia (in this example, we will be using [Alchemy](https://www.alchemy.com/) as our Ethereum node provider) and export the following environment variables:
    > ***Note:*** *This requires having access to a Bonsai API Key. To request an API key [complete the form here](https://bonsai.xyz/apply).*

    ```bash
    export BONSAI_API_KEY="YOUR_API_KEY" # see form linked in the previous section
    export BONSAI_API_URL="BONSAI_API_URL" # provided with your api key
    export ALCHEMY_API_KEY="YOUR_ALCHEMY_API_KEY" # the API_KEY provided with an alchemy account
    export ETH_WALLET_PRIVATE_KEY="YOUR_WALLET_PRIVATE_KEY" # the private hex-encoded key of your Sepolia testnet wallet
    ```

2. Build your project:

    ```bash
    cargo build
    ```

3. Deploy your contract by running:

    ```bash
    forge script script/Deploy.s.sol --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} --broadcast
    ```

     This command should output something similar to:

    ```bash
    ...
    == Logs ==
    Deployed RiscZeroGroth16Verifier to 0x5FbDB2315678afecb367f032d93F642f64180aa3
    Deployed EvenNumber to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
    ...
    ```

    Save the `EvenNumber` contract address to an env variable:

    ```bash
    export EVEN_NUMBER_ADDRESS=#COPY EVEN NUMBER ADDRESS FROM DEPLOY LOGS
    ```

    > You can also use the following command to set the contract address if you have [`jq`][jq] installed:
    >
    > ```bash
    > export EVEN_NUMBER_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "EvenNumber") | .contractAddress' ./broadcast/Deploy.s.sol/11155111/run-latest.json)
    > ```

### Interact with your testnet deployment

1. Query the state:

    ```bash
    cast call --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} ${EVEN_NUMBER_ADDRESS:?} 'get()(uint256)'
    ```

2. Publish a new state

    ```bash
    cargo run --bin publisher -- \
        --chain-id=11155111 \
        --rpc-url=https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} \
        --contract=${EVEN_NUMBER_ADDRESS:?} \
        --input=12345678
    ```

3. Query the state again to see the change:

    ```bash
    cast call --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} ${EVEN_NUMBER_ADDRESS:?} 'get()(uint256)'
    ```

[Deploy to a testnet]: #deploy-your-project-on-a-testnet
[Deploy your project to a local network]: #deploy-your-project-on-a-local-network
[RISC Zero]: https://www.risczero.com/
[contracts]: ./contracts/
[jq]: https://jqlang.github.io/jq/
[methods]: ./methods/
[tested]: ./README.md#run-the-tests
