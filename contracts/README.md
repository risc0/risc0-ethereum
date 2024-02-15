# RISC Zero Ethereum Contracts

RISC Zero provides smart contracts to verifiy [RISC Zero] receipts of execution on [Ethereum], and you can find these contracts here.

## Getting Started

If you are looking to get started using RISC Zero in the application on Ethereum, the best place to look is the [Foundry template][template].

## Key Contracts

The two main contracts you need to start verifing receipts on Ethereum are:

* [`IRiscZeroVerifier`]

  This is the interface you will use to interact with the RISC Zero verifier.
  Verfier contracts will always implement tis interface, and may be implemented by a [Groth16 verifier][`RiscZeroGroth16Verifier`], by a mock implementation, and any other verifiers we provide in the future.
* [`RiscZeroGroth16Verifier`]

  This is the verifier contracts for RISC Zero's Groth16 proof implementation. It is the first verifier implementation we have implemented for on-chain verification, and this is the contract you will use in your application.

## Using the Contracts with Foundry

You can use these contracts in [Foundry] using the `forge install` command to add this repository as a [dependency][foundry-dependencies].

```rust
forge install risc0/risc0-ethereum
```

[RISC Zero]: https://github.com/risc0/risc0
[Ethereum]: https://ethereum.org/
[template]: https://github.com/risc0/bonsai-foundry-template
[Foundry]: https://book.getfoundry.sh/
[foundry-dependencies]: https://book.getfoundry.sh/projects/dependencies
[`IRiscZeroVerifier`]: ./src/IRiscZeroVerifier.sol
[`RiscZeroGroth16Verifier`]: ./src/groth16/Groth16Verifier.sol
