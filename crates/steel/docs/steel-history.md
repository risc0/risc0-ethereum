# Steel History

## Why use Steel history?

As Steel executes a view call, it ensures integrity of the EVM state relative to a block hash or beacon block root contained in a _Steel commitment_.

When verifying a Steel call onchain, it is critical to verify the commitment, and this generally restricts how far back a Steal query can read.

* Block hash commitments are verified with the `blockhash` opcode, which has a context window of 256 blocks.
  Only Steel calls against one of the last 256 blocks (approximately ~50 minutes with 12 second block time) can be verified with this method.
* Beacon block commitments, when using L1 Ethereum, are verified with the [EIP-4788] beacon roots contract.
  This technique extends the validation time to just over 24 hours.
  See the [Steel Commitments] page for further information.

This age limit is a consequence of the way Ethereum-based blockchains store relevant block data.
For the developer, this means that, **by default, Steel proofs verified onchain can reference data no more than 24 hours old**.
To use older view call data, the Steel library has a `history` feature. 

## Overview

The Steel history feature enables the developer to query view call state older than 24 hours while still using the same Steel commitment mechanism.
This is done by separating the pinned block in Steel into two separate blocks: the execution block and the commitment block. 

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
let mut env = EthEvmEnv::builder()
    .provider(provider.clone())
    .block_number_or_tag(args.execution_block)
    .beacon_api(args.beacon_api_url)
    .commitment_block(args.commitment_block)
    .build().await?;

// Preflight the call at the execution block.
let mut contract = Contract::preflight(args.token_contract, &mut env);
```

The execution block is the block from which the view call state is retrieved
(i.e. it is the block at which the call will be executed).
The commitment block is the block used for the Steel commitment.
The commitment block has to fall within the 24 hour time window necessary for Steel commitment validation on-chain, but *crucially* the execution block can go further back on the scale of days, weeks or even months. 

## How does Steel history work?

The execution and commitment blocks are fundamentally related;
the execution block should always be an ancestor of the commitment block.
Therefore, it is possible to prove that the committed chain includes the execution block by validating a chain of beacon block roots in between the two blocks.

Steel handles this verification automatically when the history feature (feature flag: `unstable-history`) is enabled.
Steel history works backwards from the commitment block to the execution block with consecutive calls to the beacon roots contract;
validating a beacon root is a single call for every 24 hours of history.
This step takes approximately 1M cycles per 24 hours of history within the Steel guest. 

Ultimately, Steel will check the integrity of the view call data in the execution block by proving that the execution block is a canonical ancestor of the commitment block. 
Once on-chain, successfully validating the Steel commitment will prove the integrity of the block root for the commitment block.

## How far can you go back?

There is a hard limit on how far back in time you can place the execution block:
the entire validation procedure depends on [EIP-4788] which was introduced with the [Cancun upgrade] on March 13 2024;
this is the furthest that Steel history can go back.

## How much does Steel history cost? 

For the host, the developer needs to specify valid RPC URLs for both an archive execution node and a beacon node.
You can see an example in the [publisher.rs] CLI args for the [erc20-counter] example.

The greatest API cost will likely be from the beacon API endpoint.
For each block between the commitment block and the execution block, Steel will query the full beacon block for verification.
Please bear in mind that the wider the gap between the execution block and the commitment block, the larger the load on the beacon endpoint will be. 

In terms of compute, the number of cycles for the Steel guest will also increase linearly with the number of blocks between the commitment block and the execution block.
For every extra 24 hours of history, this is around 1 million cycles in the Steel guest. Please note this cycle count is without the Keccak precompile scheduled for release in Q1 2025. Once the Keccak precompile is available, the cycle count should be significantly reduced.

## Enabling Steel History

To enable Steel History, you can add these feature flags to the relevant `Cargo.toml` file:

```toml
risc0-steel = { git = "https://github.com/risc0/risc0-ethereum.git", tag = "vX.Y.Z", features = ["unstable-history"] }
```

**To see example code, please see the [publisher app] and its [Cargo.toml] for the erc20-counter example which has been updated to support Steel history.**

---

<----[Steel Commitments](./steel-commitments.md) | [Steel README](../README.md) ---->

[EIP-4788]: https://eips.ethereum.org/EIPS/eip-4788
[beacon chain]: https://ethereum.org/en/roadmap/beacon-chain/
[Steel Commitments]: ./steel-commitments.md
[Cancun upgrade]: https://ethereum.org/en/history/#cancun-summary
[publisher.rs]: ../../../examples/erc20-counter/apps/src/bin/publisher.rs
[erc20-counter]: ../../../examples/erc20-counter/README.md
[publisher app]: ../../../examples/erc20-counter/apps/README.md
[Cargo.toml]: ../../../examples/erc20-counter/apps/Cargo.toml
