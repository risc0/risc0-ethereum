# Examples

## [ERC20 Balance Query](./erc20/README.md)

This introductory example illustrates how to use [Steel] to directly query the `balanceOf` function of any ERC20 token contract, providing a verifiable proof of a user's token balance.

## [ERC20 Counter with Off-Chain Proofs](./erc20-counter/README.md)

Explore a more advanced interaction between [Steel] and a custom Ethereum smart contract. This counter contract utilizes off-chain [Steel] proofs to:
- Increment a counter based on user-submitted proofs.
- Verify ERC20 token ownership (minimum 1 token required) before incrementing.
- Leverage RISC Zero as a [coprocessor] for efficient proof generation and verification.

## [Compound Token Stats (APR Proof)](./token-stats/README.md)

This example shows how the [Steel] library can be used to call multiple view functions of a contract.
This example generates a proof of a [Compound] cToken's APR (Annual Percentage Rate), showcasing the potential for on-chain verification of complex financial metrics.

## [DAO Governance with Off-chain Proofs](./governance/README.md)

This example contains a modified version of OpenZeppelin's [Governor] contract, which takes gas intensive signature verification off-chain whilst maintaining the same trust assumptions. This contract leverages RISC Zero as a [coprocessor] for generating and verifying these proofs.

[coprocessor]: https://www.risczero.com/news/a-guide-to-zk-coprocessors-for-scalability
[Governor]: https://docs.openzeppelin.com/contracts/4.x/api/governance#governor
[Steel]: ../steel
[Compound]: https://compound.finance/
