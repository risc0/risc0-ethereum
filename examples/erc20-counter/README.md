# ERC20-Counter Example

This example implements a counter that increments based on off-chain RISC Zero [Steel] proofs submitted to the [Counter] contract.
The contract interacts with ERC-20 tokens, using [Steel] proofs to verify that an account holds at least 1 token before incrementing the counter.

## Overview

The [Counter] contract is designed to interact with the Ethereum blockchain, leveraging the power of RISC Zero [Steel] proofs to perform a specific operation: incrementing a counter based on the token holdings of an account.

### Contract Functionality

#### Increment Counter

The core functionality of the [Counter] contract is to increment an internal counter whenever a valid proof was submitted.
This proof must demonstrate that a specified account holds at least one unit of a particular ERC-20 token.
The contract ensures that the counter is only incremented when the proof is verified and the condition of holding at least one token is met.

#### Steel Proof Submission

Users or entities can submit proofs to the [Counter] contract.
These proofs are generated off-chain using the RISC Zero zkVM.
The proof encapsulates the verification of an account's token balance without exposing the account's details or requiring direct on-chain queries.

#### Token Balance Verification

Upon receiving a [Steel] proof, the [Counter] contract decodes the proof and validates it against the contract's state at a certain block height.
This ensures that the account in question actually holds at least one token at the time the proof was generated.

#### Counter Management

The contract maintains an internal counter, which is publicly viewable.
This counter represents the number of successful verifications that have occurred.
The contract includes functionality to query the current value of the counter at any time.

## Dependencies

To get started, you need to have the following installed:

- [Rust]
- [Foundry]
- [RISC Zero]

### Configuring Bonsai

***Note:*** *To request an API key [complete the form here](https://bonsai.xyz/apply).*

With the Bonsai proving service, you can produce a [Groth16 SNARK proof] that is verifiable on-chain.
You can get started by setting the following environment variables with your API key and associated URL.

```bash
export BONSAI_API_KEY="YOUR_API_KEY" # see form linked above
export BONSAI_API_URL="BONSAI_URL" # provided with your api key
```

## Deploy Your Application

When you're ready, follow the [deployment guide] to get your application running on [Sepolia] or a local network.

[Foundry]: https://getfoundry.sh/
[Groth16 SNARK proof]: https://www.risczero.com/news/on-chain-verification
[RISC Zero]: https://dev.risczero.com/api/zkvm/install
[Sepolia]: https://www.alchemy.com/overviews/sepolia-testnet
[deployment guide]: ./deployment-guide.md
[Rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[Counter]: ./contracts/src/Counter.sol
[Steel]: https://www.risczero.com/blog/introducing-steel
