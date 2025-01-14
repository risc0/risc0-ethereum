# Steel History

## How old can view call data be in Steel? 

Steel commitments are necessary to ensure the integrity of view call data by confirming the block hash or the beacon block root, returned by the RPC provider, matches the on-chain available block information. Due to this necessity of checking against available on-chain block information, there is currently a age limit on view call data. When using the `blockhash` opcode, there is a context window of 256 blocks, meaning that the Steel proof is only valid for view call data within the last 256 blocks (approximately ~50 minutes with 12 second block time). When using L1 Ethereum, the [EIP-4788] beacon roots contract allows validation of the block root on the [beacon chain]. This technique extends the validation time to just over 24 hours. See the [Steel Commitments] page for further information.

This age limit is a fundamental consequence of the way Ethereum based blockchains store relevant block data. For the developer, this means that the view call data for a Steel execution proof can be a maximum of 24 hours old before the proof can not be verified on-chain.  To use older view call data, the Steel library has a `history` feature. 

## Steel History Overview

The Steel history feature enables the developer to query view call state older than 24 hours while still using the same Steel commitment mechanism. This is done by separating the pinned block in Steel into two separate blocks: the execution block and the commitment block. 

Without the Steel history feature enabled, the pinned block is *both* the block from which the view call state is retrieved and the block used for the Steel commitment:

```rust
// WITHOUT STEEL HISTORY
// Create an EVM environment from that provider defaulting to the latest block.
let mut env = EthEvmEnv::builder()
    .provider(provider.clone())
    .build()
    .await?;

// Preflight the call at the pinned block, default latest.
let mut contract = Contract::preflight(args.token_contract, &mut env);
```

With the Steel history feature enabled, the developer must specify both the execution block *and* the commitment block:

```rust
/// WITH STEEL HISTORY
let builder = EthEvmEnv::builder()
    .provider(provider.clone())
    .block_number_or_tag(args.execution_block);

#[cfg(any(feature = "beacon", feature = "history"))]
let builder = builder.beacon_api(args.beacon_api_url);
#[cfg(feature = "history")]
let builder = builder.commitment_block(args.commitment_block);

let mut env = builder.build().await?;

// Preflight the call at the execution block.
let mut contract = Contract::preflight(args.token_contract, &mut env);
```

The execution block is the block from which the view call state is retrieved. The commitment block is the block used for the Steel commitment. The commitment block has to fall within the 24 hour time window necessary for Steel commitment validation on-chain, but *crucially* the execution block can go further back on the scale of days, weeks or even months. 

## How does the Steel history feature work?

The execution and commitment blocks are fundamentally related; the execution block should always be an ancestor of the commitment block. Therefore, it is possible to prove that the commitment block block root is canonical with the execution block block root by validating each beacon block root in between the two blocks.

Steel handles this verification automatically when the history feature is enabled. Steel history works backwards from the commitment block to the execution block with consecutive calls to the beacon roots contract; validating a beacon root is a single call for every 24 hours of history and this step takes approximately 1M cycles within the Steel guest. 

Ultimately, Steel will check the integrity of the view call data in the execution block by:

1. proving that the execution block is a canonical ancestor of the commitment block
2. carrying out the standard Steel commitment validation on-chain proving the integrity of the block root for the commitment block

### How far can you go back? Is there a hard limit?

There is a hard limit: the entire validation procedure depends on [EIP-4788] which was introduced with the [Cancun upgrade] in March 2024.

## What does Steel history require? 

On the host side, the developer needs to specify valid RPC URLs for both an archive execution node and a beacon node. You can see an example in the [publisher.rs] CLI args for the [erc20-counter] example.

## How much does Steel history cost? 

The greatest API cost will likely be from the beacon API endpoint. For each block between the commitment block and the execution block, Steel will query the full beacon block for verification. Please bear in mind that the wider the gap between the execution block and the commitment block, the larger the load on the beacon endpoint will be. 

In terms of compute, the number of cycles for the Steel guest will also increase linearly with the number of blocks between the commitment block and the execution block. For every extra 24 hours of history, this is around 1 million cycles in the Steel guest.

## How to enable the Steel history feature?

To enable Steel History, you can add these feature flags to the relevant `Cargo.toml` file:

```toml
[features]
history = ["risc0-steel/unstable-history"]
beacon = []
```

**To see example code, please see the [publisher app] and its [Cargo.toml] for the erc20-counter example which has been updated to support Steel history.**

---

<----[Steel Commitments](./steel-commitments.md) | [Steel README](../README.md) ---->

[EIP-4788]: https://eips.ethereum.org/EIPS/eip-4788
[beacon chain]: https://ethereum.org/en/roadmap/beacon-chain/
[Steel Commitments]: ./steel-commitments.md
[Cancun upgrade]: https://ethereum.org/en/history/#cancun-summary
[publisher.rs]: ../../examples/erc20-counter/apps/src/bin/publisher.rs
[erc20-counter]: ../../examples/erc20-counter/README.md
[publisher app]: ../../examples/erc20-counter/apps/README.md
[Cargo.toml]: ../../examples/erc20-counter/apps/Cargo.toml
