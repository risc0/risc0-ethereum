# Apps

In typical applications, an off-chain app is needed to do two main actions:

* Produce a proof (see [proving options]).
* Send a transaction to Ethereum to execute your on-chain logic.

This template provides the `publisher` CLI as an example application to execute these steps.
In a production application, a back-end server or your dApp client may take on this role.

## Publisher

The [`publisher` CLI][publisher], is an example application that produces a proof and publishes it to your app contract.

### Usage

Run the `publisher` with:

```sh
cargo run --bin publisher
```

```text
$ cargo run --bin publisher -- --help

Usage: publisher --chain-id <CHAIN_ID> --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY> --rpc-url <RPC_URL> --contract <CONTRACT> --input <INPUT>

Options:
      --chain-id <CHAIN_ID>
          Ethereum chain ID
      --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY>
          Ethereum Node endpoint [env: ETH_WALLET_PRIVATE_KEY=]
      --rpc-url <RPC_URL>
          Ethereum Node endpoint
      --contract <CONTRACT>
          Application's contract address on Ethereum
  -i, --input <INPUT>
          The input to provide to the guest binary
  -h, --help
          Print help
  -V, --version
          Print version
```

[proving-options]: https://dev.risczero.com/api/generating-proofs/proving-options
[publisher]: ./src/bin/publisher.rs
