# RISC Zero Ethereum

[RISC Zero] is a zero-knowledge verifiable general computing platform, with [Ethereum] integration.
This repository contains [Solidity verifier contracts][contracts], [Steel] EVM view call library, and supporting code.

If you are looking to get started using RISC Zero in the application on Ethereum, the best place to look is the [Foundry template][template].

You can also find the documentation for RISC Zero, including guides for [writing zkVM programs][risc0-quickstart], [using the Bonsai prover][bonsai-quickstart], and more at [dev.risczero.com].

## Contracts

RISC Zero's Ethereum contracts, including the on-chain verifier for all RISC Zero Groth16 proofs, can be found in the [contracts] directory.

## Steel

Steel lets Solidity developers effortlessly scale their applications by moving computation offchain without compromising on onchain security. Steel drastically reduces gas costs and this enables previously impossible applications.

Steel now lives in its own repository. Check out [github.com/boundless-xyz/steel](https://github.com/boundless-xyz/steel)

[RISC Zero]: https://github.com/risc0/risc0
[Ethereum]: https://ethereum.org/
[contracts]: ./contracts
[examples directory]: ./examples
[template]: https://github.com/risc0/risc0-foundry-template
[dev.risczero.com]: https://dev.risczero.com
[risc0-quickstart]: https://dev.risczero.com/api/zkvm/quickstart
[bonsai-quickstart]: https://dev.risczero.com/bonsai
[alloy]: https://github.com/alloy-rs
