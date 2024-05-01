# 

<!-- TODO update this -->

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

<!-- TODO this is wrong, update -->
To run the example, which queries the USDT balance of `0x9737100D2F42a196DE56ED0d1f6fF598a250E7E4` on Ethereum, execute the following command:

```bash
RPC_URL=https://ethereum-rpc.publicnode.com RUST_LOG=info cargo run --release
```

<!-- TODO this is for other example -->
The output should resemble the following:

```text
2024-03-12T11:06:14.549457Z  INFO view_call::host: preflight 'balanceOf(address)' method by 0xf08A50178dfcDe18524640EA6618a1f965821715 on 0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0
For block 5470081 `balanceOf(address)` returns: 399534748753251
Running the guest with the constructed input:
View call result: 399534748753251
2024-03-12T11:06:17.018205Z  INFO executor: risc0_zkvm::host::server::exec::executor: execution time: 538.5ms
2024-03-12T11:06:17.018224Z  INFO executor: risc0_zkvm::host::server::session: number of segments: 6
2024-03-12T11:06:17.018227Z  INFO executor: risc0_zkvm::host::server::session: total cycles: 5505024
2024-03-12T11:06:17.018229Z  INFO executor: risc0_zkvm::host::server::session: user cycles: 4179903
2024-03-12T11:06:17.018231Z  INFO executor: risc0_zkvm::host::server::session: cycle efficiency: 75%
```

[install-rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[cargo-binstall]: https://github.com/cargo-bins/cargo-binstall#cargo-binaryinstall
