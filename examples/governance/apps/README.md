# Apps

In typical applications, an off-chain app is needed to do two main actions:

* Produce a proof e.g. by sending a proof request to [Bonsai].
* Send a transaction to Ethereum to execute your on-chain logic.

This template provides the `publisher` CLI as an example application to execute these steps.
In a production application, a back-end server or your dApp client may take on this role.

## Publisher

The [`publisher` CLI][publisher], is an example application that sends an off-chain proof request to the [Bonsai] proving service, and publishes the received proofs to your deployed app contract.

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

## Library

We provide a small rust [library] containing utility functions to help with sending off-chain proof requests to the Bonsai proving service and publish the received proofs directly to a deployed app contract on Ethereum.

As we continue to improve the [risc0-zkvm] and [bonsai-sdk] crates, we will absorb some of the functionality provided here into those crates.

[publisher]: ./src/bin/publisher.rs
[Bonsai]: https://dev.bonsai.xyz/
[library]: ./src/lib.rs
[risc0-zkvm]: https://docs.rs/risc0-zkvm/latest/risc0_zkvm/
[bonsai-sdk]: https://docs.rs/bonsai-sdk/latest/bonsai_sdk/
