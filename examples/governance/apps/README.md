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

## Vote Data Tools

This repository contains two Rust scripts for handling voting-related operations:

1. `generate_vote_data.rs`: Generates vote data for a proposal.
2. `generate_proposal_id.rs`: Generates a proposal ID.

## Usage

### Generate Vote Data

```sh
cargo run --bin generate_vote_data -- --nonce <NONCE> --proposal-id <PROPOSAL_ID> --support <SUPPORT>
```

Where `<SUPPORT>` is one of: `against`, `for`, or `abstain`.

### Generate Proposal ID

```sh
cargo run --bin generate_proposal_id
```

## Requirements

- Rust
- Required dependencies (see `Cargo.toml`)

## Deployment-specific Configuration

These scripts contain hardcoded values that need to be adjusted for your specific deployment:

1. In `generate_vote_data.rs`:
   - `voter_address`: Currently set to `"4DAfB91f6682136032C004768837e60Bc099E52C"`
   - `verifyingContract` in `build_domain_separator()`: Currently set to `"5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9"` (RiscZeroGovernor address)
   - `chainId`: Currently set to `31337` (local Hardhat/Foundry chain)

2. In `generate_proposal_id.rs`:
   - The target address in `create_proposal_params()`: Currently set to `"0000000000000000000000000000000000000004"`

Ensure you update these values to match your specific deployment environment before using the scripts.

[proving-options]: https://dev.risczero.com/api/generating-proofs/proving-options
[publisher]: ./src/bin/publisher.rs
