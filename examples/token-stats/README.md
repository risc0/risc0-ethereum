# Compound Token Stats (APR Proof)

**An example that calls multiple view functions on the Compound USDC contract to compute the APR.**

## Prerequisites

To get started, you need to have Rust installed. If you haven't done so, follow the instructions [here][install-rust].

Next, you will also need to have the `cargo-risczero` tool installed following the instructions [here][install-risczero].

You'll also need access to an Ethereum Mainnet RPC endpoint. You can for example use [ethereum-rpc.publicnode.com](https://ethereum-rpc.publicnode.com/) or a commercial RPC provider like [Alchemy](https://www.alchemy.com/).

## Run the example

To run the example, which computes the current APR of the Compound USDC Token [`0xc3d688B66703497DAA19211EEdff47f25384cdc3`](https://etherscan.io/token/0xc3d688B66703497DAA19211EEdff47f25384cdc3) on Ethereum, execute the following command:

```bash
RPC_URL=https://ethereum-rpc.publicnode.com RUST_LOG=info cargo run --release
```

The output should resemble the following:

```text
2024-08-05T17:58:28.709271Z  INFO risc0_steel::host: Environment initialized for block 20464007    
2024-08-05T17:58:28.709406Z  INFO risc0_steel: Commitment to block 0xba19f4d5d1aabd1e4ddca7263f1307cfdec1252041395edfc1d8507eaf142cf8    
2024-08-05T17:58:28.709502Z  INFO risc0_steel::contract: Executing preflight calling 'getUtilization()' on 0xc3d688B66703497DAA19211EEdff47f25384cdc3    
Call getUtilization() Function on 0xc3d6…cdc3 returns: 715303307067353898
2024-08-05T17:58:29.974428Z  INFO risc0_steel::contract: Executing preflight calling 'getSupplyRate(uint256)' on 0xc3d688B66703497DAA19211EEdff47f25384cdc3    
Call getSupplyRate(uint256) Function on 0xc3d6…cdc3 returns: 1179470191
Running the guest with the constructed input:
2024-08-05T17:58:31.587359Z  INFO executor: risc0_zkvm::host::server::exec::executor: execution time: 196.721584ms
2024-08-05T17:58:31.587385Z  INFO executor: risc0_zkvm::host::server::session: number of segments: 11
2024-08-05T17:58:31.587388Z  INFO executor: risc0_zkvm::host::server::session: total cycles: 11534336
2024-08-05T17:58:31.587390Z  INFO executor: risc0_zkvm::host::server::session: user cycles: 8885255
Proven APR calculated is: 3.7195771943376%
```

[install-rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[install-risczero]: https://dev.risczero.com/api/zkvm/install
