![Steel banner](./steel-banner.png)

# Steel - Boundless runtime for EVM apps

## Introducing Steel, a production-ready EVM execution prover

Steel is a production-ready EVM execution prover designed to bring boundless runtime to all EVM apps. Using execution proofs, Steel enables EVM apps to run completely offchain, while preserving onchain security.  With Steel, you can prove correct smart contract execution without re-execution, allowing blockchain developers unbounded computation over on-chain data.. 

Our partners are already developing game-changing applications with Steel.  One application has shown gas savings of 1.2 billion gas for a contract call using around 400,000 SLOADs. 1.2 billion gas is around 30 blocks worth of execution and this can be verified onchain in one proof, that costs under $10 to generate, and less than 300k gas to verify. Steel unlocks boundless application runtime, without rollups, without centralization, without re-writing your smart contracts, and without writing ZK circuits. The brakes are off.

## Getting Started with Steel

The recommended place is to start is with the [Steel examples](../examples/README.md), specifically the [ERC20 Counter](../examples/erc20-counter/README.md) example. 

The [create-steel-app](book/create-steel-app/) script will allow you to set up the erc20-counter example locally in one command:

`sh -c "$(curl -fsSL PLACEHOLDER_URL)"`

This example act as your skeleton project structure for further development. Once the script is finished, you can run through a test workflow with either local proving or Bonsai proving. 

You can read more about create-steel-app on its [README](book/create-steel-app/README.md), and the documentation below uses the ERC20-counter example as a guide to explain Steel and how it works.

## Documentation 

This documentation covers the core concepts of Steel. After reading, you will understand how Steel creates verifiable EVM execution proofs allowing you to carry out execution off-chain verfiably. 

   - [Introducing Steel 1.0](https://risczero.com/blog/introducing-steel-1.0) (blog post)
   - [What is Steel?](book/what-is-steel.md)
   - [How does Steel work?](book/how-does-steel-work.md)
     - [View Calls](book/how-does-steel-work.md#view-calls)
     - [Proving EVM execution within the zkVM](book/how-does-steel-work.md#proving-evm-execution-within-the-zkvm)
     - [Verifying the Proof On-Chain](book/how-does-steel-work.md#verifying-the-proof-on-chain)
   - [Steel Commitments](book/steel-commitments.md)
     - [Trust Anchor: The Blockhash](book/steel-commitments.md#steels-trust-anchor-the-blockhash)
     - [What is a Steel Commitment?](book/steel-commitments.md#what-is-a-steel-commitment)
     - [Validation of Steel Commitments](book/steel-commitments.md#validation-of-steel-commitments)

## Further Reading & Ask Questions

The RISC Zero [dev docs](https://dev.risczero.com/api/) are a great place to start to understand the zkVM in detail. If you have any questions, and/or just want to hang out with other builders, please join the [RISC Zero Discord](https://discord.com/invite/risczero).