![Steel banner](./steel-banner.png)

# Steel: The ZK Coprocessor for EVM Apps

> "Unbounded EVM computation made simple"

Steel lets Solidity developers effortlessly scale their applications by moving computation offchain without compromising on onchain security. Steel drastically reduces gas costs and this enables previously impossible applications.

Steel pulls state from any EVM chain, performs verifiable computation across multiple blocks offchain, and generates concise execution proofs. Developers simply verify these proofs onchain to access boundless compute, without worrying about gas limits.

> ** Example **
>
> A single Steel proof has verified a computation equivalent to 30 Ethereum blocks—saving 1.2 billion gas—generated for under $10 and verified onchain for under 300k gas.

## Getting Started with Steel

The recommended place is to start is [Steel examples], specifically the [ERC20 Counter] example.

The [create-steel-app] script will allow you to set up the erc20-counter example locally in one command:

```sh
sh <(curl -fsSL https://raw.githubusercontent.com/risc0/risc0-ethereum/refs/heads/release-2.1/crates/steel/docs/create-steel-app/create-steel-app)
```

This example acts as your skeleton project structure for further development. Once the script is finished, you can run through a test workflow with either local proving or Bonsai proving. The documentation below uses the ERC20-counter example as a guide to explain Steel in detail.

## Documentation

Steel Documentation can be found on the [Boundless Docs]. `risc0-steel` also has [crate documentation]. This documentation covers the core concepts of Steel. After reading, you will understand how Steel creates verifiable EVM execution proofs allowing you to carry out execution off-chain verifiably.

- [Introducing Steel 1.0] (blog post)
- [What is Steel?]
- [How does Steel work?]
- [Steel Commitments]
- [Steel History]
- [Steel Events]

## Further Reading & Ask Questions

The RISC Zero [dev docs][dev-docs] are a great place to start to understand the zkVM in detail. If you have any questions, and/or just want to hang out with other builders, please join the [RISC Zero Discord][risczero-discord].

[Steel examples]: https://github.com/risc0/risc0-ethereum/blob/main/examples
[ERC20 Counter]: https://github.com/risc0/risc0-ethereum/blob/main/examples/erc20-counter
[create-steel-app]: https://github.com/risc0/risc0-ethereum/blob/main/crates/steel/docs/create-steel-app
[crate documentation]: https://risc0.github.io/risc0-ethereum/risc0_steel/
[Introducing Steel 1.0]: https://risczero.com/blog/introducing-steel-1.0]
[Boundless Docs]: https://docs.beboundless.xyz/developers/steel/what-is-steel
[What is Steel?]: https://docs.beboundless.xyz/developers/steel/what-is-steel
[How does Steel work?]: https://docs.beboundless.xyz/developers/steel/how-it-works
[Steel Commitments]: https://docs.beboundless.xyz/developers/steel/commitments
[Steel History]: https://docs.beboundless.xyz/developers/steel/history
[Steel Events]: https://docs.beboundless.xyz/developers/steel/events
[dev-docs]: https://dev.risczero.com/api/
[risczero-discord]: https://discord.com/invite/risczero
