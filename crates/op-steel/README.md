# op-steel

A Rust library for integrating Optimism's Layer 2 blockchain with Steel, RISC Zero's production-ready smart contract execution prover.

## Overview

op-steel extends [Steel](https://github.com/risc0/risc0-ethereum/tree/main/crates/steel) to work with Optimism's Layer 2 blockchain. Steel enables EVM apps to run offchain while preserving onchain security through execution proofs. op-steel brings these capabilities to the Optimism ecosystem.

The library provides tools and utilities for:
- Interacting with Optimism's Layer 2 blockchain
- Validating block headers and state
- Working with Optimism dispute games
- Building and verifying proofs for L2 blocks using Steel's proving system

## Features

- **Steel Integration**: 
  - Leverage Steel's execution proving system for Optimism L2 operations
  - Generate verifiable proofs of correct smart contract execution
  - Maintain onchain security while performing computation offchain
- **Dispute Game Integration**: 
  - Find and validate dispute games
  - Support for latest, finalized, and specific game indices
  - Automatic verification against L1 OptimismPortal contract

## Usage

Usage of op-steel is very similar to Steel.
See the [Steel README](https://github.com/risc0/risc0-ethereum/tree/main/crates/steel#readme) for more details.

### Basic Example

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

### Working with Dispute Games

By relying on the existing dispute game functionality it is seamlessly possible to verify OP contract execution on L1. 

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
