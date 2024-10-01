# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### ⚡️ Features

### 🛠 Fixes

- Return specific error, when no `Contract::preflight` was called.

### 🚨 Breaking Changes

- `CallBuilder::call` in the guest now returns an error that needs to be handled, before it just panicked.

## [0.13.0](https://github.com/risc0/risc0-ethereum/releases/tag/steel-v0.13.0) - 2024-09-10

### ⚡️ Features

- Add support for creating a commitment to a beacon block root using `EvmEnv::into_beacon_input`, which can be verified using the [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788) beacon roots contract.
- Add the `EvmEnvBuilder` to simplify the creation of an `EvmEnv` on the host.
- If an individual `eth_getProof` RPC call contains many storage keys, it will be automatically split. The chunk size can be configured using the `EvmEnvBuilder`.
- Add `CallBuilder::prefetch_access_list` and `CallBuilder::call_with_prefetch` for that host that prefetch storage proofs and values to drastically reduce the number of RPC calls.

### 🚨 Breaking Changes

- `EvmInput` has been changed to an `enum` to support different input types for the guest, such as the new `BeaconInput`. This changes the binary input data, but does not require any code changes.
- `SolCommitment` has been renamed to `Commitment`.

## [0.12.0](https://github.com/risc0/risc0-ethereum/releases/tag/steel-v0.12.0) - 2024-08-09

### ⚡️ Features

- Replace `ethers` dependency completely with `alloy`.
- Make `host` functions `async`.
- Add support to build `EvmEnv` from any `alloy` provider.
- Add more efficient RLP-based serialization for the header.

### 🛠 Fixes

- Store the commitment inside the `EvmEnv`.
- Use `eth_getTransactionCount` and `eth_getBalance` instead of `eth_getProof` to query basic account information.
- Switch tests from pre-recorded RPC responses to `Anvil`.

### 🚨 Breaking Changes

- `EthEvmEnv::from_rpc` now accepts a `Url` instead of a `&str` for the HTTP RPC endpoint.
- `EvmEnv::from_provider` now requires an `alloy` provider, and the block number parameter has been changed to a `BlockNumberOrTag`.
- `EvmEnv::sol_commitment` has been replaced with `EvmEnv::commitment` (to get a reference), or `EvmEnv::into_commitment` (to consume and return the commitment).
- `ETH_SEPOLIA_CHAIN_SPEC` and `ETH_MAINNET_CHAIN_SPEC` have been moved to the `ethereum` module.
- `CachedProvider` has been removed completely. As alternatives, you can:
  - Use `anvil --fork-url https://ethereum-rpc.publicnode.com@20475759` to create a cached fork for block `20475759`. 
  - Cache the RPC responses on an HTTP level using [Tower](https://crates.io/crates/tower) or a caching forward proxy.
- The host functions are now `async` instead of blocking:
```rust
// Create an EVM environment from an RPC endpoint and a block number or tag.
let mut env = EthEvmEnv::from_rpc(args.rpc_url, BlockNumberOrTag::Latest).await?;
//  The `with_chain_spec` method is used to specify the chain configuration.
env = env.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

// Preflight the call to prepare the input that is required to execute the function in
// the guest without RPC access. It also returns the result of the call.
let mut contract = Contract::preflight(CONTRACT, &mut env);
let returns = contract.call_builder(&CALL).from(CALLER).call().await?;

// Finally, construct the input from the environment.
let input = env.into_input().await?;
```

## [0.11.1](https://github.com/risc0/risc0-ethereum/releases/tag/steel-v0.11.1) - 2024-06-25
