> [!IMPORTANT]  
> `main` is the development branch for this repository.
> Application developers should use the [latest release](https://github.com/risc0/risc0-ethereum/releases) instead.

# RISC Zero Ethereum Toolkit

[RISC Zero] is a zero-knowledge verifiable general computing platform. This repo contains and indexes a number of tools for integrating the [RISC Zero zkVM] with [Ethereum] including the [Steel View Call] library, [Solidity verifier contracts][contracts], [Relay] service, and supporting libraries.

If you are looking to get started using RISC Zero in the application on Ethereum, the best place to look is the [Foundry template][template].

You can also find the documentation for RISC Zero, including guides for [writing zkVM programs][risc0-quickstart], [using the Bonsai prover][bonsai-quickstart], and more at [dev.risczero.com].

## Steel - View Call Proof Library
Steel is a powerful library for querying the state of Ethereum, or any other EVM-based blockchain, and performing verifiable computation over that state in the [RISC Zero zkVM]. This enables dapp and other on-chain protocols to move an arbitrary amount of execution off chain, sidestepping block and transaction size limits.  Steel leverages the [alloy] library to make its use Solidity-friendly.

## Contracts

RISC Zero's Ethereum contracts, including the on-chain verifier for verifying all RISC Zero zkVM proofs, can be found in the [contracts] directory.

## Relay

The Relay is a service that can be run to accept proving requests from on-chain events or via REST Request, and post receipts to the developer's application contract as a callback.
It represents one way of accepting requests, and posting proofs to Ethereum.
It is also possible to write your application without using the Relay.

You can find and overview of how the Relay works, [in our documentation][relay-overview].
Source code for the Relay is in the [relay] directory.

# Other RISC Zero Ethereum Tools
This section indexes additional tools available for zkVM developers building on Ethereum or other EVM chains. 

## Foundry Template
The RISC Zero [Foundry Template] is a [Foundry]-based project template containing a number of smart contracts, examples, and other features to make it easy for developers integrate the zkVM with Ethereum applications.

## Zeth
[Zeth] is the first ever [Type 1] zkEVM. Built on top of the RISC Zero zkVM, Zeth is capable of proving the valid execution of  Ethereum or [Optimism] blocks.

[RISC Zero]: https://github.com/risc0/risc0
[RISC Zero zkVM]: https://dev.risczero.com/api/zkvm/
[Ethereum]: https://ethereum.org/
[contracts]: ./contracts
[relay]: ./relay
[Steel View Call]: ./steel-view-call
[template]: https://github.com/risc0/bonsai-foundry-template
[dev.risczero.com]: https://dev.risczero.com
[risc0-quickstart]: https://dev.risczero.com/api/zkvm/quickstart
[bonsai-quickstart]: https://dev.risczero.com/api/bonsai/quickstart
[relay-overview]: https://dev.risczero.com/api/bonsai/bonsai-on-eth#bonsai-relay
[alloy]: https://github.com/alloy-rs
[Foundry Template]: https://github.com/risc0/risc0-foundry-template
[Foundry]: https://github.com/foundry-rs/foundry
[Zeth]: https://github.com/risc0/zeth
[Type 1]: https://vitalik.eth.limo/general/2022/08/04/zkevm.html#type-1-fully-ethereum-equivalent
[Optimism]: https://www.optimism.io/
