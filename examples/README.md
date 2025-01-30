# Examples
This directory includes three example uses of Steel. Each example demonstrates a different concept of Steel. 

## [ERC20 Balance Query](./erc20/README.md)

This introductory example illustrates how to use [Steel] to directly query the `balanceOf` function of any ERC20 token contract, providing a verifiable proof of a user's token balance.

## [ERC20 Counter with Off-Chain Proofs](./erc20-counter/README.md)

Explore a more advanced interaction between [Steel] and a custom Ethereum smart contract. This counter contract utilizes off-chain [Steel] proofs to:
- Increment a counter based on user-submitted proofs.
- Verify ERC20 token ownership (minimum 1 token required) before incrementing.
- Leverage RISC Zero as a [coprocessor] for efficient proof generation and verification.

## [Event Query](./events/README.md)

This example illustrates how to use [Steel] to query and process events.
This example computes the total USDT transferred in a block by evaluating the ERC20 `Transfer` event emitted by the corresponding contract.

## [Compound Token Stats (APR Proof)](./token-stats/README.md)

This example shows how the [Steel] library can be used to call multiple view functions of a contract.
This example generates a proof of a [Compound] cToken's APR (Annual Percentage Rate), showcasing the potential for on-chain verification of complex financial metrics.

[coprocessor]: https://risczero.com/blog/a-guide-to-zk-coprocessors-for-scalability
[Steel]: ../crates/steel
[Compound]: https://compound.finance/
