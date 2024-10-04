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

Usage: publisher [OPTIONS] --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY> --eth-rpc-url <ETH_RPC_URL> --counter <COUNTER> --token-contract <TOKEN_CONTRACT> --account <ACCOUNT>

Options:
      --eth-wallet-private-key <ETH_WALLET_PRIVATE_KEY>
          Ethereum private key
          
          [env: ETH_WALLET_PRIVATE_KEY=]

      --eth-rpc-url <ETH_RPC_URL>
          Ethereum RPC endpoint URL
          
          [env: ETH_RPC_URL=]

      --beacon-api-url <BEACON_API_URL>
          Optional Beacon API endpoint URL
          
          When provided, Steel uses a beacon block commitment instead of the execution block. This allows proofs to be validated using the EIP-4788 beacon roots contract.
          
          [env: BEACON_API_URL=]

      --counter-address <COUNTER_ADDRESS>
          Address of the Counter verifier contract

      --token-contract <TOKEN_CONTRACT>
          Address of the ERC20 token contract

      --account <ACCOUNT>
          Address to query the token balance of

  -h, --help
          Print help (see a summary with '-h')
```

[publisher]: ./src/bin/publisher.rs
[Counter]: ../contracts/src/Counter.sol
