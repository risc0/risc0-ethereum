# RISC Zero View Call Proofs ERC20 Example Ethereum Deployment Guide

> **Note: This software is not production ready. Do not use in production.**

Welcome to the [RISC Zero] View Call Proofs ERC20 Example Ethereum Deployment guide!

You can either:

- [Deploy to a local network]
- [Deploy to a testnet]

## Deploy on a local network

You can deploy your contracts and run an end-to-end test or demo as follows:

1. Install `ganache`: 
    You must first install [Node.js] >= v16.0.0 and npm >= 7.10.0.
    To install Ganache globally, run:
    ```
    npm install ganache --global
    ```

2. Start a local testnet with `ganache` by running:

    ```bash
    ganache
    ```

    Once ganache is started, look at its logs and copy any of the Private Keys. You'll need one for the next step.
    Then, keep it running in the terminal, and switch to a new terminal.

2. Set your environment variables:
    > ***Note:*** *This requires having access to a Bonsai API Key. To request an API key [complete the form here](https://bonsai.xyz/apply).*

    ```bash
    # Ganache sets up a number of private keys, use the one you copied during the previous step.
    export ETH_WALLET_PRIVATE_KEY="YOUR_GANACHE_PRIVATE_KEY"
    export BONSAI_API_KEY="YOUR_API_KEY" # see form linked in the previous section
    export BONSAI_API_URL="BONSAI_API_URL" # provided with your api key
    ```

4. Deploy the ERC20 Toyken contract:
    ```
    forge script --rpc-url http://localhost:8545 --broadcast script/DeployERC20.s.sol
    ```
    Save the `ERC20 Toyken` contract address to an env variable:
    ```
    export TOYKEN_ADDRESS=#COPY ERC20 TOYKEN ADDRESS FROM DEPLOY LOGS
    ```

    > You can also use the following command to set the contract address if you have [`jq`][jq] installed:
    >
    > ```bash
    > export TOYKEN_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "ERC20") | .contractAddress' ./broadcast/DeployERC20.s.sol/1337/run-latest.json)
    > ```

5. Mint some Toyken:
    ```
    cast send --private-key $ETH_WALLET_PRIVATE_KEY --rpc-url http://localhost:8545 $TOYKEN_ADDRESS 'mint(address, uint256)' 0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4 100
    ```
    > Now the account at address `0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4` should have 100 Toyken.

3. Build the project:
    
    Before building the project, make sure the contract address on both the [methods/guest/src/bin/balance_of.rs] as well [apps/src/bin/publisher.rs] is set to the value of your deployed `TOYKEN_ADDRESS`:

    ```rust
    const CONTRACT: Address = address!("<PLACE YOUR TOYKEN ADDRESS HERE>");
    ```
    
    Then run:

    ```bash
    cargo build
    ```

4. Deploy the Counter contract by running:

    ```bash
    forge script --rpc-url http://localhost:8545 --broadcast script/DeployCounter.s.sol
    ```

    This command should output something similar to:

    ```bash
    ...
    == Logs ==
    Deployed RiscZeroGroth16Verifier to 0x5FbDB2315678afecb367f032d93F642f64180aa3
    Deployed Counter to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
    ...
    ```

    Save the `Counter` contract address to an env variable:

    ```bash
    export COUNTER_ADDRESS=#COPY COUNTER ADDRESS FROM DEPLOY LOGS
    ```

    > You can also use the following command to set the contract address if you have [`jq`][jq] installed:
    >
    > ```bash
    > export COUNTER_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/DeployCounter.s.sol/1337/run-latest.json)
    > ```

### Interact with your local deployment

1. Query the state:

    ```bash
    cast call --rpc-url http://localhost:8545 ${COUNTER_ADDRESS:?} 'get()(uint256)'
    ```

2. Publish a new state

    ```bash
    cargo run --bin publisher -- \
        --chain-id=1337 \
        --rpc-url=http://localhost:8545 \
        --contract=${COUNTER_ADDRESS:?} \
        --account=0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4
    ```

3. Query the state again to see the change:

    ```bash
    cast call --rpc-url http://localhost:8545 ${COUNTER_ADDRESS:?} 'get()(uint256)'
    ```

## Deploy your project on a testnet

You can deploy the Counter contract on a testnet such as `Sepolia` and run an end-to-end test or demo as follows:
> ***Note***: we'll be using an existing ERC20 contract for this example, specifically the USDT ERC20 contract deployed on Sepolia at address [0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0].

1. Get access to Bonsai and an Ethereum node running on a given testnet, e.g., Sepolia (in this example, we will be using [Alchemy](https://www.alchemy.com/) as our Ethereum node provider) and export the following environment variables:
    > ***Note:*** *This requires having access to a Bonsai API Key. To request an API key [complete the form here](https://bonsai.xyz/apply).*

    ```bash
    export BONSAI_API_KEY="YOUR_API_KEY" # see form linked in the previous section
    export BONSAI_API_URL="BONSAI_API_URL" # provided with your api key
    export ALCHEMY_API_KEY="YOUR_ALCHEMY_API_KEY" # the API_KEY provided with an alchemy account
    export ETH_WALLET_PRIVATE_KEY="YOUR_WALLET_PRIVATE_KEY" # the private hex-encoded key of your Sepolia testnet wallet
    ```

2. Build the project:
    
    Before building the project, make sure the contract address on both the [methods/guest/src/bin/balance_of.rs] as well [apps/src/bin/publisher.rs] is set to `aA8E23Fb1079EA71e0a56F48a2aA51851D8433D0`
    
    ```rust
    const CONTRACT: Address = address!("aA8E23Fb1079EA71e0a56F48a2aA51851D8433D0");
    ```
    
    Then run:

    ```bash
    cargo build
    ```

3. Deploy the Counter contract by running:

    ```bash
    forge script script/DeployCounter.s.sol --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} --broadcast
    ```

     This command should output something similar to:

    ```bash
    ...
    == Logs ==
    Deployed RiscZeroGroth16Verifier to 0x5FbDB2315678afecb367f032d93F642f64180aa3
    Deployed Counter to 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
    ...
    ```

    Save the `Counter` contract address to an env variable:

    ```bash
    export COUNTER_ADDRESS=#COPY COUNTER ADDRESS FROM DEPLOY LOGS
    ```

    > You can also use the following command to set the contract address if you have [`jq`][jq] installed:
    >
    > ```bash
    > export COUNTER_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "Counter") | .contractAddress' ./broadcast/DeployCounter.s.sol/11155111/run-latest.json)
    > ```

### Interact with your testnet deployment

1. Query the state:

    ```bash
    cast call --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} ${COUNTER_ADDRESS:?} 'get()(uint256)'
    ```

2. Publish a new state

    ```bash
    cargo run --bin publisher -- \
        --chain-id=11155111 \
        --rpc-url=https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} \
        --contract=${COUNTER_ADDRESS:?} \
        --account=0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4
    ```

3. Query the state again to see the change:

    ```bash
    cast call --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} ${COUNTER_ADDRESS:?} 'get()(uint256)'
    ```

[Deploy to a testnet]: #deploy-your-project-on-a-testnet
[Deploy your project to a local network]: #deploy-your-project-on-a-local-network
[RISC Zero]: https://www.risczero.com/
[Node.js]: https://nodejs.org/
[jq]: https://jqlang.github.io/jq/
[methods]: ./methods/
[tested]: ./README.md#run-the-tests
[0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0]: https://sepolia.etherscan.io/address/0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0#code
[methods/guest/src/bin/balance_of.rs]: ./methods/guest/src/bin/balance_of.rs
[apps/src/bin/publisher.rs]: ./apps/src/bin/publisher.rs