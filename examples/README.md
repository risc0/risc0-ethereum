# Examples

This directory includes three example uses of Steel. Each example demonstrates a different concept of Steel.

### [ERC20 Balance Query](./erc20/README.md)

This introductory example illustrates how to use [Steel] to directly query the `balanceOf` function of any ERC20 token
contract, providing a verifiable proof of a user's token balance.

### [ERC20 Counter with Off-Chain Proofs](./erc20-counter/README.md)

Explore a more advanced interaction between [Steel] and a custom Ethereum smart contract. This counter contract utilizes
off-chain [Steel] proofs to:

- Increment a counter based on user-submitted proofs.
- Verify ERC20 token ownership (minimum 1 token required) before incrementing.
- Leverage RISC Zero as a [coprocessor] for efficient proof generation and verification.

### [Event Query](./events/README.md)

This example illustrates how to use [Steel] to query and process events.
This example computes the total USDT transferred in a block by evaluating the ERC20 `Transfer` event emitted by the corresponding contract.

### [Compound Token Stats (APR Proof)](./token-stats/README.md)

This example shows how the [Steel] library can be used to call multiple view functions of a contract.
This example generates a proof of a [Compound] cToken's APR (Annual Percentage Rate), showcasing the potential for
on-chain verification of complex financial metrics.

## ERC20 Balance Query using [op-steel]

### [L2 Execution - L2 Verification](./op/l2)

This example shows how to use [op-steel] to query the `balanceOf` function of an ERC20 token on OP, providing a proof
that can be verified on OP.

### [L1 Execution - L2 Verification](./op/l1-to-l2)

This example shows how to use [op-steel] to query the `balanceOf` function of an ERC20 token on Ethereum and how the
generated proof can be verified on OP.

### [L2 Execution - L1 Verification](./op/l2-to-l1)

This example shows how to use [op-steel] to query the `balanceOf` function of an ERC20 token on OP and how the generated
proof can be verified on Ethereum.

[coprocessor]: https://risczero.com/blog/a-guide-to-zk-coprocessors-for-scalability
[Steel]: ../crates/steel
[Compound]: https://compound.finance/
[op-steel]: ../crates/op-steel
