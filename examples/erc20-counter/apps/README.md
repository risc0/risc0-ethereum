# Apps

## Publisher

The [`publisher` CLI][publisher], is an example application that sends an off-chain proof request to the RISC Zero zkVM, and publishes the received proofs to your deployed [Counter] contract.

### Usage

Run the `publisher` with:

```sh
cargo run --bin publisher
```

```text
$ cargo run --bin publisher -- --help

Usage: publisher --chain-id <CHAIN_ID> --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY> --rpc-url <RPC_URL> --contract <CONTRACT> --account <ACCOUNT>

Options:
      --chain-id <CHAIN_ID>
          Ethereum chain ID
      --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY>
          Ethereum Node endpoint [env: ETH_WALLET_PRIVATE_KEY=0x2a5369d12693b5a8c4e1d0e85788bea5ccb1c90fb6f82bb33a25a216e6cce071]
      --rpc-url <RPC_URL>
          Ethereum Node endpoint [env: RPC_URL=]
      --contract <CONTRACT>
          Counter's contract address on Ethereum
      --account <ACCOUNT>
          Account address to read the balance_of on Ethereum
  -h, --help
          Print help
  -V, --version
          Print version
```

## Library

We provide a small rust [library] containing utility functions to help with sending 
transactions to a deployed app contract on Ethereum.

[publisher]: ./src/bin/publisher.rs
[library]: ./src/lib.rs
[Counter]: ../contracts/Counter.sol
