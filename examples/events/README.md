# Events Example

**An example that computes the total USDT transferred in a block by evaluating the ERC20 `Transfer` event emitted by the corresponding contract.**

## Prerequisites

To get started, you need to have Rust installed. If you haven't done so, follow the instructions [here][install-rust].

Next, you will also need to have the `cargo-risczero` tool installed following the instructions [here][install-risczero].

You'll also need access to an Ethereum Mainnet RPC endpoint. You can for example use [ethereum-rpc.publicnode.com](https://ethereum-rpc.publicnode.com/) or a commercial RPC provider like [Alchemy](https://www.alchemy.com/).

## Run the example

To run the example, which computes the total USDT transferred in the latest block on Ethereum, execute the following command:

```bash
RPC_URL=https://ethereum-rpc.publicnode.com RUST_LOG=info cargo run --release
```

The output should resemble the following:

```text
2025-01-23T17:45:09.325435Z  INFO risc0_steel::host::builder: Environment initialized with block 21688768 (0x74886aafc56111558c80aad6d998f214fb3f3fc70bd65164a81eb89c6aafaba6)    
2025-01-23T17:45:09.404058Z  INFO host: Contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 emitted 13 events with signature: Transfer(address,address,uint256)    
2025-01-23T17:45:09.797803Z  INFO risc0_zkvm::host::server::exec::executor: execution time: 95.332417ms
2025-01-23T17:45:09.801306Z  INFO host: Total USDT transferred in block 0x74886aafc56111558c80aad6d998f214fb3f3fc70bd65164a81eb89c6aafaba6: 505404191183 
```

[install-rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[install-risczero]: https://dev.risczero.com/api/zkvm/install
