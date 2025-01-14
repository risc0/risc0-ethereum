# Steel History

Steel commitments are necessary to ensure the integrity of view call data by confirming either the block hash or the beacon block root returned by the RPC matches the on-chain available block information.  Due to this necessity of checking against available on-chain block information, there is currently a age limit on view call data. When using the `blockhash` opcode, there is a context window of 256 blocks, meaning that the Steel proof is only valid for view call data within the last 256 blocks (approximately ~50 minutes with 12 second block time). When using L1 Ethereum, the [EIP-4788] beacon roots contract allows validation of the block root on the [beacon chain]. This technique extends the validation time to just over 24 hours. See the [Steel Commitments] page for further information.

This age limit is a fundamental consequence of the way Ethereum based blockchains store relevant block data. For the developer, this means that the view call data, for a Steel execution proof, can be a maximum of 24 hours old. This constrains the developer to view call data younger than 24 hours.  To use older view call data, the Steel library has a `history` feature. 

## Steel History

Steel history defines a separation of the execution block from the commitment block. 

Without the Steel history feature enabled, the block that is pinned for the preflight call is the block from which the view call state is retrieved and also the block that is used for the Steel commitment:

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

With the Steel history feature enabled, the developer must specify the execution block *and* the commitment block:

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

## How does the Steel history feature work (in the guest)?

The execution and commitment blocks are fundamentally related. The execution block is always an ancestor of the commitment block. Therefore, it is possible to prove that the commitment block block root is canonical with the execution block block root. Steel handles this automatically within the Steel guest when the history feature is enabled. Steel works backwards from the commitment block to the execution block with consecutive calls to the beacon roots contract; validating a beacon root is a single call for every 24 hours of history and this step takes approximately 1M cycles. Ultimately, Steel will prove that the execution block is a canonical ancestor of the commitment block. Once on-chain, the standard Steel commitment procedure will then prove the validity of the block root for the commitment block and by verifying the Steel proof, the developer can be sure of the integrity of the view call data at the execution block.


## What does Steel history require (for the host)? 

On the host side, the developer needs to specify valid RPC URLs for both an archive execution node and a beacon node. For each block between the commitment block and the execution block, Steel will query the full beacon block for verification. Please bear in mind that the wider the gap between the execution block and the commitment block, the larger the load on the beacon endpoint will be. 

## How much does Steel history cost? 

So both the cycles and the API calls are linear in the number of days you go back... Which can get expensive.


## How to enable Steel history?

```toml
[features]
history = ["risc0-steel/unstable-history"]
beacon = []
```

## Example runthrough

publisher.rs




## Misc

the block from which the view call state is retrieved, and the commitment block, the block that is used for the Steel commitment. The commitment block still has to fall within the 24 hour time window necessary for Steel commitment validation on-chain, but *crucially* the execution block can go further back on the scale of days, weeks and even months. The further back the execution block is, the larger the number of cycles in the Steel zkVM guest and the larger the RPC load becomes. The fundamental execution proof verification on-chain costs the same amount of gas, no matter how far your execution block goes. 

---

<----[Steel Commitments](./steel-commitments.md) | [Steel README](../README.md) ---->


[Steel Commitments]: ./steel-commitments.md
[EIP-4788]: https://eips.ethereum.org/EIPS/eip-4788
[beacon chain]: https://ethereum.org/en/roadmap/beacon-chain/