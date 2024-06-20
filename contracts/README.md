# RISC Zero Ethereum Contracts

RISC Zero provides smart contracts to verify [RISC Zero] receipts of execution on [Ethereum], and you can find these contracts here.

## Getting Started

If you are looking to get started using RISC Zero in an application on Ethereum, the best place to look is the [Foundry template][template].

## Using the Contracts with Foundry

You can use these contracts in [Foundry] using the `forge install` command to add this repository as a [dependency][foundry-dependencies].

```sh
# Use @ref to install from any git ref, such as main or a different release.
forge install risc0/risc0-ethereum@v1.0.0
```

## Verifier Interface

### [IRiscZeroVerifier]

This is the interface you will use to interact with the RISC Zero verifier.
Verifier contracts will implement this interface.
Behind this interface may be the [Groth16 verifier][RiscZeroGroth16Verifier], a mock implementation, and any other verifier we provide in the future.

## Verifier Implementations

### [RiscZeroGroth16Verifier]

This is the verifier contract for [RISC Zero's Groth16 proof system][groth16-article].
It is the first verifier implementation we have implemented for on-chain verification, and this is the contract you will use in your deployed application.

### [RiscZeroMockVerifier]

This is a verifier contract you can use in tests.
It allows you to produce mock proofs that will pass verification, allowing you to test logic controlled by the zkVM without needing to produce proofs.

## Version management

The [RiscZeroVerifierEmergencyStop] and [RiscZeroVerifierRouter]
contracts are used to implement a version management system, with appropriate safeguards in place.
You can read more about the version management design in the [version management design](./version-management-design.md).

### [RiscZeroVerifierEmergencyStop]

This contract acts as a proxy for an [IRiscZeroVerifier] contract, with the addition of an emergency stop function.
When the emergency stop is activated, this proxy will be permanently disabled, and revert on all verify calls.

### [RiscZeroVerifierRouter]

Allows for multiple verifier implementations to live behind a single address implementing the [IRiscZeroVerifier] interface.
Using the verifier selector included in the seal, it will route each `verify` call to the appropriate implementation.

[RISC Zero]: https://github.com/risc0/risc0
[Ethereum]: https://ethereum.org/
[template]: https://github.com/risc0/bonsai-foundry-template
[Foundry]: https://book.getfoundry.sh/
[foundry-dependencies]: https://book.getfoundry.sh/projects/dependencies
[groth16-article]: https://www.risczero.com/news/on-chain-verification
[IRiscZeroVerifier]: ./src/IRiscZeroVerifier.sol
[RiscZeroGroth16Verifier]: ./src/groth16/Groth16Verifier.sol
[RiscZeroMockVerifier]: ./src/test/RiscZeroMockVerifier.sol
[RiscZeroVerifierEmergencyStop]: ./src/RiscZeroVerifierEmergencyStop.sol
[RiscZeroVerifierRouter]: ./src/RiscZeroVerifierRouter.sol
