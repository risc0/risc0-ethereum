> [!IMPORTANT]
> `main` is the development branch.
> Application developers should use the [latest release](https://github.com/risc0/risc0-ethereum/releases) instead.

# RISC Zero Ethereum

[RISC Zero] is a zero-knowledge verifiable general computing platform, with [Ethereum] integration.
This repository contains [Solidity verifier contracts][contracts], [Steel] EVM view call library, and supporting code.

If you are looking to get started using RISC Zero in the application on Ethereum, the best place to look is the [Foundry template][template].

You can also find the documentation for RISC Zero, including guides for [writing zkVM programs][risc0-quickstart], [using the Bonsai prover][bonsai-quickstart], and more at [dev.risczero.com].

## Contracts

RISC Zero's Ethereum contracts, including the on-chain verifier for all RISC Zero Groth16 proofs, can be found in the [contracts] directory.

## Steel

A powerful library for querying and generating verifiable proofs over Ethereum or other EVM-based blockchain state. It leverages [alloy], giving developers a familiar and high quality interface for querying Ethereum via view calls. By moving execution off-chain, Steel significantly reduces gas costs and enables novel Ethereum use cases without compromising security.

You can install [Steel] with `cargo add risc0-steel`, check out the examples in the [examples directory](./examples/erc20-counter).

[RISC Zero]: https://github.com/risc0/risc0
[Ethereum]: https://ethereum.org/
[contracts]: ./contracts
[Steel]: ./steel
[template]: https://github.com/risc0/bonsai-foundry-template
[dev.risczero.com]: https://dev.risczero.com
[risc0-quickstart]: https://dev.risczero.com/api/zkvm/quickstart
[bonsai-quickstart]: https://dev.risczero.com/bonsai
[alloy]: https://github.com/alloy-rs
