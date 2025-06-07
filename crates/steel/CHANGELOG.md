# Changelog

All notable changes to this project will be documented in this file.

## [2.2.0](https://github.com/risc0/risc0-ethereum/releases/tag/v2.2.0)

### ⚡️ Features

- **Update to alloy 1.0:** This release updates Steel's alloy dependency to 1.0 :tada:

### 🛠️ Fixes

- **Improve Validation in `Steel.validatedCommitment`:** Update the Steel beacon block commit validation to always revert on invalid timestamps [#605](https://github.com/risc0/risc0-ethereum/pull/605)
    - Prior to this fix a beacon block commitment with a zero digest and invalid timestamp would be accepted by `Steel.validateCommitment`, violating the semantics of `validateCommitment`.
    - No correct Steel guest would create such a commitment, and no opening proofs can be generated against it.

## [2.1.0](https://github.com/risc0/risc0-ethereum/releases/tag/v2.1.0)

### ⚡️ Features

- Introduce the `EvmFactory` trait (`EthEvmFactory`) to abstract over different EVM implementations, enabling better code reuse and support for chain-specific logic like Optimism's transaction types and state handling.
- Introduce the capability to query Ethereum events. The new `Event` allows to query events of a specific type in Steel. Its usage is very similar to the existing `Contract`, during the preflight step and in the guest. This functionality is currently marked unstable and must be enabled using the `unstable-event` feature.
- Add support for the Prague Ethereum fork on Mainnet, Sepolia, and Holešky testnets via updated `EthChainSpec`.
- Enable KZG point evaluation precompile.
- Improve `HistoryCommit` proof generation logic. The algorithm now reliably chains state proofs backward from the commitment block by querying the beacon roots contract state to verify linkage to the execution block commitment, replacing the previous forward-stepping approach.
- Introduce `SteelVerifier::verify_with_config_id` on host and guest to allow verifying a `Commitment` against an explicitly provided configuration ID.
- Stabilize `event`, `history` and `verifier`.

### 🛠️ Fixes

- Add verification of the `Commitment::configID` field in `SteelVerifier::verify` on both host and guest against the environment's configuration ID. This corrects an omission where commitments with mismatched configurations could pass verification.
- Fix error in storage proof processing where necessary Merkle proof nodes could be discarded if the same storage trie was accessed via multiple accounts and different storage keys. Proof nodes for shared tries are now correctly merged.

### 🚨 Breaking Changes

- **`EvmFactory` Abstraction:** The core types `EvmEnv`, `EvmInput`, `BlockInput`, `Contract`, `CallBuilder`, `Account`, `Event`, `SteelVerifier`, and host builder methods are now generic over an `EvmFactory` implementation (e.g., `EthEvmFactory`) instead of just a block header type. This is a fundamental change affecting environment creation, contract interaction, and type signatures throughout the library.
- **`CallBuilder` API:** The API for configuring contract calls has changed significantly. Fluent methods like `.from()`, `.gas()`, `.value()`, `.gas_price()` have been removed. Call parameters **must** now be set by directly modifying the public `tx` field of the `CallBuilder` instance before execution (e.g., `builder.tx.caller = my_address; builder.tx.gas_limit = 100_000;`). Consult the specific `Tx` type documentation for your `EvmFactory` (e.g., `revm::context::TxEnv` for `EthEvmFactory`) for available fields.
- **`EvmBlockHeader` Trait:** The trait now requires an associated type `Spec` and mandates implementing `fn to_block_env(&self, spec: Self::Spec) -> BlockEnv` instead of the previous `fill_block_env`.
- **`ChainSpec` Generics:** `ChainSpec` is now generic over the specification type instead of being fixed to `revm::primitives::SpecId`. Use the provided type aliases `EthChainSpec` (for `SpecId`). The hashing mechanism for `ChainSpec::digest()` has changed.
- Chain specification handling refactored:
  - Removed `HostEvmEnv::with_chain_spec`. Chain specification must now be provided via the new `.chain_spec()` builder method *before* calling `.build()`. `EvmEnvBuilder` now track the chain spec via a type parameter.
  - Methods like `EvmInput::into_env` now require a `&ChainSpec<...>` argument to reconstruct the environment in the guest, ensuring consistent configuration.
- Replace `HostEvmEnv::extend(&mut self, other: Self)` with `HostEvmEnv::merge(self, other: Self) -> Result<Self>`. The new `merge` function consumes both environment instances and returns a new merged instance upon success, whereas `extend` modified the existing environment in place. This change improves safety and clarity when combining environments, especially after parallel preflight operations.
- Remove deprecated `EvmEnv::into_beacon_input`.
- **Alloy 1.0/0.14 Updates:**
  - Methods like `abi_decode` no longer take a `validate: bool` argument (use `abi_decode(&data)`).
  - Contract call results now directly return the value, not a single-element tuple (use `result` instead of `result._0`).

### ⚙️ Miscellaneous

- Updated major dependencies: `alloy*` (to 0.14/1.0), `revm` (to 22.0).
- Added new dependencies: `alloy-evm`, `alloy-op-evm`, `op-revm`, `bincode`.

## [1.3.0](https://github.com/risc0/risc0-ethereum/releases/tag/v1.3.0)

### ⚡️ Features

- Introduce the `SteelVerifier`, which acts as a built-in Steel `Contract` to verify Steel commitments. It is used like any other `Contract`, during the preflight step and in the guest. This functionality is currently marked unstable and must be enabled using the `unstable-verifier` feature.

## [1.2.0](https://github.com/risc0/risc0-ethereum/releases/tag/v1.2.0)

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
