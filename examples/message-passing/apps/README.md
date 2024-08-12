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

Usage: publisher --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY> --rpc-url <RPC_URL> --contract <CONTRACT> --token <TOKEN> --account <ACCOUNT>

Options:
      --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY>
          Ethereum Node endpoint [env: ETH_WALLET_PRIVATE_KEY=]
      --rpc-url <RPC_URL>
          Ethereum Node endpoint [env: RPC_URL=]
      --contract <CONTRACT>
          Counter's contract address on Ethereum
      --token <TOKEN>
          ERC20 contract address on Ethereum
      --account <ACCOUNT>
          Account address to read the balance_of on Ethereum
  -h, --help
          Print help
  -V, --version
          Print version
```

[publisher]: ./src/bin/publisher.rs
[Counter]: ../contracts/Counter.sol
