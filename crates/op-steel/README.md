# OP-Steel

A Rust library for integrating Optimism's Layer 2 blockchain with Steel, RISC Zero's production-ready smart contract execution prover.

## Overview

OP-Steel extends [Steel](https://github.com/risc0/risc0-ethereum/tree/main/crates/steel) to work with Optimism's Layer 2 blockchain and any OP Stack-compatible chains. Steel provides a generic tool to interact with EVM-compatible chains, enabling offchain execution of EVM apps while preserving onchain security through execution proofs.

While you can use Steel directly to query and verify on the same chain (including OP chains), OP-Steel makes this process more convenient by including pre-configured OP network settings. The main advantage of OP-Steel, however, is its ability to perform **cross-chain queries** between Optimism and Ethereum, a feature not available in Steel alone.

## Features

- **Steel Integration**:
  - Leverage Steel's execution proving system for Optimism L2 operations
  - Generate verifiable proofs of correct smart contract execution
  - Maintain onchain security while performing computation offchain
- **Cross-Chain Queries**:
  - Perform cross-chain queries between Optimism and Ethereum
  - Seamlessly verify OP contract execution on Ethereum L1
- **Dispute Game Integration**:
  - Find and validate dispute games
  - Support for latest, finalized, and specific game indices
  - Automatic verification against the L1 `OptimismPortal` contract
- **OP Stack Compatibility**:
  - Use OP-Steel with OP-Mainnet and any OP Stack-compatible chains

## Usage

Usage of OP-Steel is very similar to Steel. See the [Steel README](https://github.com/risc0/risc0-ethereum/tree/main/crates/steel#readme) for more details.

### Querying and Verifying on the Same Chain

If you only need to query and verify on the same chain (e.g., OP-Mainnet), you can use Steel directly. However, OP-Steel simplifies this process by providing pre-configured OP network settings.

```rust
// Create an OP environment
let env = OpEvmEnv::builder()
    .rpc(Url::parse("https://optimism-rpc.publicnode.com")?)
    .build()
    .await?
    // Apply chain configuration
    .with_chain_spec(&OP_MAINNET_CHAIN_SPEC);

// Implement steel functionality
let contract = Contract::new(CONTRACT, &env);
contract.call_builder(&CALL).from(CALLER).call();

// Convert to input format for the guest
let input = env.into_input().await?;
```

### Cross-Chain Queries (OP to Ethereum)

OP-Steel enables cross-chain queries, such as verifying OP contract execution on Ethereum L1. This is a key feature that Steel alone does not provide.

```rust
// Create an OP environment referencing a dispute game
let env = OpEvmEnv::builder()
    .dispute_game_from_rpc(
        portal_address,
        "https://ethereum-rpc.publicnode.com".parse()?
    )
    .rpc("https://optimism-rpc.publicnode.com".parse()?)
    .game_index(DisputeGameIndex::Latest)
    .build()
    .await?;

// Implement steel functionality
let contract = Contract::new(CONTRACT, &env);
contract.call_builder(&CALL).from(CALLER).call();

// Convert to input format for the guest
let input = env.into_input().await?;
```

## Learn More

- [Steel Documentation](https://github.com/risc0/risc0-ethereum/tree/main/crates/steel#readme) - Learn about the core Steel system
- [RISC Zero Developer Docs](https://dev.risczero.com/api/) - Detailed documentation about the underlying zkVM
- [Optimism Documentation](https://community.optimism.io/) - Learn about Optimism's L2 system
