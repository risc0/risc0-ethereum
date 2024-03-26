# RISC Zero View Call Proofs ERC20-Counter Example

> ***WARNING***: This software is still experimental, we do not recommend it for production use.

This example implements a counter that increments based on off-chain view call proofs submitted to the [Counter] contract.
The contract interacts with ERC-20 tokens, using view call proofs to verify that an account holds at least 1 token before incrementing the counter. This contract leverages RISC Zero as a [coprocessor] for generating and verifying these proofs.

## Overview

The [Counter] contract is designed to interact with the Ethereum blockchain, leveraging the power of RISC Zero view call proofs to perform a specific operation: incrementing a counter based on the token holdings of an account.

### Contract Functionality

#### Increment Counter: 
The core functionality of the [Counter] contract is to increment an internal counter whenever a valid view call proof is submitted. This proof must demonstrate that a specified account holds at least one unit of a particular ERC-20 token. The contract ensures that the counter is only incremented when the proof is verified and the condition of holding at least one token is met.

#### View Call Proof Submission: 
Users or entities can submit view call proofs to the [Counter] contract. These proofs are generated off-chain using the RISC Zero zkVM. The proof encapsulates the verification of an account's token balance without exposing the account's details or requiring direct on-chain queries.

#### Token Balance Verification: 
Upon receiving a view call proof, the [Counter] contract decodes and verifies it against the specified ERC-20 token contract. This process involves validating the proof against the contract's state at a specific block height, ensuring the account in question indeed holds at least one token at the time of the proof's generation.

#### Counter Management: 
The contract maintains an internal counter, which is publicly viewable. This counter represents the number of successful verifications that have occurred. The contract includes functionality to query the current value of the counter at any time.

## Dependencies

First, [install Rust] and [Foundry], and then restart your terminal.

```sh
# Install Rust
curl https://sh.rustup.rs -sSf | sh
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
```

Next, you will need to install the `cargo risczero` tool.
We'll use [`cargo binstall`][cargo-binstall] to get `cargo-risczero` installed, and then install the `risc0` toolchain.
See [RISC Zero installation] for more details.

```sh
cargo install cargo-binstall
cargo binstall cargo-risczero
cargo risczero install
```

Now you have all the tools you need to develop and deploy an application with [RISC Zero].

### Configuring Bonsai

***Note:*** *To request an API key [complete the form here](https://bonsai.xyz/apply).*

With the Bonsai proving service, you can produce a [Groth16 SNARK proof] that is verifiable on-chain.
You can get started by setting the following environment variables with your API key and associated URL.

```bash
export BONSAI_API_KEY="YOUR_API_KEY" # see form linked above
export BONSAI_API_URL="BONSAI_URL" # provided with your api key
```

## Deploy Your Application

When you're ready, follow the [deployment guide] to get your application running on [Sepolia].

[Bonsai]: https://dev.bonsai.xyz/
[Foundry]: https://getfoundry.sh/
[Get Docker]: https://docs.docker.com/get-docker/
[Groth16 SNARK proof]: https://www.risczero.com/news/on-chain-verification
[RISC Zero Verifier]: https://github.com/risc0/risc0/blob/release-0.21/bonsai/ethereum/contracts/IRiscZeroVerifier.sol
[RISC Zero installation]: https://dev.risczero.com/api/zkvm/install
[RISC Zero zkVM]: https://dev.risczero.com/zkvm
[RISC Zero]: https://www.risczero.com/
[Sepolia]: https://www.alchemy.com/overviews/sepolia-testnet
[app contract]: ./contracts/
[cargo-binstall]: https://github.com/cargo-bins/cargo-binstall#cargo-binaryinstall
[coprocessor]: https://www.risczero.com/news/a-guide-to-zk-coprocessors-for-scalability
[deployment guide]: /deployment-guide.md
[developer FAQ]: https://dev.risczero.com/faq#zkvm-application-design
[image-id]: https://dev.risczero.com/terminology#image-id
[install Rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[journal]: https://dev.risczero.com/terminology#journal
[publisher]: ./apps/README.md
[zkVM program]: ./methods/guest/
[Counter]: ./contracts/Counter.sol