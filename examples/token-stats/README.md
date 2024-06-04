# Compound Token Stats (APR Proof)

**An example that calls multiple view function on the Compound USDC contract to compute the APR.**

> ***WARNING***: This software is still experimental, we do not recommend it for production use.

## Prerequisites

To get started, you need to have Rust installed. If you haven't done so, follow the instructions [here][install-rust].

Next, install the `cargo risczero` tool. We'll use `cargo binstall` to facilitate this. Detailed instructions can be found at [cargo-binstall].

```bash
cargo install cargo-binstall
cargo binstall cargo-risczero
```

Finally, install the `risc0` toolchain with the following command:

```bash
cargo risczero install
```

You'll also need access to an Ethereum RPC node, such as through [Alchemy](www.alchemy.com).

## Run the example

To run the example, which computes the current APR of the Compound USDC Token `0xc3d688B66703497DAA19211EEdff47f25384cdc3` on Ethereum, execute the following command:

```bash
RPC_URL=https://ethereum-rpc.publicnode.com RUST_LOG=info cargo run --release
```

The output should resemble the following:

```text
2024-06-04T20:47:18.785315Z  INFO risc0_steel::contract: Executing preflight for 'getUtilization()' on contract 0xc3d688B66703497DAA19211EEdff47f25384cdc3    
2024-06-04T20:47:20.979605Z  INFO risc0_steel::contract: Executing preflight for 'getSupplyRate(uint256)' on contract 0xc3d688B66703497DAA19211EEdff47f25384cdc3    
Running the guest with the constructed input:
2024-06-04T20:47:23.011329Z  INFO executor: risc0_zkvm::host::server::exec::executor: execution time: 443.8825ms
2024-06-04T20:47:23.011368Z  INFO executor: risc0_zkvm::host::server::session: number of segments: 11
2024-06-04T20:47:23.011371Z  INFO executor: risc0_zkvm::host::server::session: total cycles: 11534336
2024-06-04T20:47:23.011373Z  INFO executor: risc0_zkvm::host::server::session: user cycles: 8945420
Proven APR calculated is: 6.7249996533936%
```

[install-rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[cargo-binstall]: https://github.com/cargo-bins/cargo-binstall#cargo-binaryinstall
