# EIP-4788 Counter Example

**An example that verifies a Steel Beacon commitment using EIP-4788's Beacon roots contract.**

## Prerequisites

To get started, you need to have Rust installed. If you haven't done so, follow the instructions [here][install-rust].

Next, you will also need to have the `cargo-risczero` tool installed following the instructions [here][install-risczero].

You'll also need access to an Ethereum RPC endpoint as well as a Beacon API endpoint.

## Run the example

- Ensure that the `.env` file contains the correct config.
- Set the `ETH_WALLET_PRIVATE_KEY`variable to a valid private key holding some funds.
- Configure [Bonsai](https://bonsai.xyz) using `BONSAI_API_KEY` and `BONSAI_API_URL`.
- The verifying `Counter` contract can be deployed using the `DeployCounter` script.
- The host program can be executed by specifying the address of the deployed `Counter` and the address of the account to verify the balance of.

[install-rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[install-risczero]: https://dev.risczero.com/api/zkvm/install
