# RISC Zero Ethereum Contracts

RISC Zero provides smart contracts to verifiy [RISC Zero] receipts of execution on [Ethereum], and you can find these contracts here.

## Getting Started

If you are looking to get started using RISC Zero in the application on Ethereum, the best place to look is the [Foundry template][template].

## Key Contracts

The two main contracts you need to start verifing receipts on Ethereum are:

* [`IRiscZeroVerifier`]

  This is the interface you will use to interact with the RISC Zero verifier.
  Verfier contracts will implement this interface.
  Behind this interface may be the [Groth16 verifier][`RiscZeroGroth16Verifier`], a mock implementation, and any other verifier we provide in the future.

* [`RiscZeroGroth16Verifier`]

  This is the verifier contract for [RISC Zero's Groth16 proof implementation][groth16-article].
  It is the first verifier implementation we have implemented for on-chain verification, and this is the contract you will use in your deployed application.

## Using the Contracts with Foundry

You can use these contracts in [Foundry] using the `forge install` command to add this repository as a [dependency][foundry-dependencies].

```bash
forge install risc0/risc0-ethereum
```

[RISC Zero]: https://github.com/risc0/risc0
[Ethereum]: https://ethereum.org/
[template]: https://github.com/risc0/bonsai-foundry-template
[Foundry]: https://book.getfoundry.sh/
[foundry-dependencies]: https://book.getfoundry.sh/projects/dependencies
[`IRiscZeroVerifier`]: ./src/IRiscZeroVerifier.sol
[`RiscZeroGroth16Verifier`]: ./src/groth16/Groth16Verifier.sol
[groth16-article]: https://www.risczero.com/news/on-chain-verification
