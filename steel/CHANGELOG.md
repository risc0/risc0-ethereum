# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### ⚡️ Features

- Introduce `HistoryInput`, which decouples the EVM execution block from the commitment block. This allows verification against a commitment that is more recent than the execution, allowing secure interaction with the historical state. This functionality is currently marked "unstable" and must be enabled using the `unstable-history` feature.
- Make `EvmEnvBuilder` public.

### 🚨 Breaking Changes

- Remove `EvmEnv::from_rpc` and `EvmEnv::from_provider` which have been deprecated since `0.12.0`.

## [1.1.4](https://github.com/risc0/risc0-ethereum/releases/tag/v1.1.4) - 2024-10-07

### ⚡️ Features

- Add `try_call()` method to `CallBuilder` when explicit error handling is necessary.
- Make `BeaconInput`, `BlockInput` and `StateDb` public.
- Implement custom `Debug` formatter for `Commitment`.
- Implement `Deref` for `RlpHeader`.

### 🛠 Fixes

- Return specific error, when no `Contract::preflight` was called.
- Use `decode_exact` when RLP-decoding the MPT leaves.

### 🚨 Breaking Changes

- The Solidity `Commitment` now also contains a hash of the chain specification including chain ID, and fork configuration.
- Instead of committing to the root of a beacon block referenced by its timestamp, we commit to the root of a beacon block referenced by its child timestamp, or equivalently, we commit to the root of the parent beacon block referenced by its timestamp. While this may sound counterintuitive, this is exactly how the [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788) beacon root contract stores its data. This makes the verification side in Solidity much easier and less expensive, and gets rid of the weird code that was necessary to query the child of a beacon block during creation.
- Introduce the `ComposeInput` as a generalized type to represent different commitments. The `BeaconInput` is now a `ComposeInput`. This changes the binary input data, but does not require any code changes.

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
