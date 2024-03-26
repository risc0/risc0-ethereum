# Examples

## [erc20]
This example uses the [view call] library to query the ERC20 interface's `balanceOf` method for a specific address within the RISC Zero zkVM. 

## [erc20-counter]
This example implements a counter that increments based on off-chain view call proofs submitted to the [Counter] contract.
The contract interacts with ERC-20 tokens, using view call proofs to verify that an account holds at least 1 token before incrementing the counter. This contract leverages RISC Zero as a [coprocessor] for generating and verifying these proofs.

[erc20]: ./erc20/README.md
[erc20-counter]: ./erc20-counter/README.md
[Counter]: ./erc20-counter/contracts/Counter.sol
[coprocessor]: https://www.risczero.com/news/a-guide-to-zk-coprocessors-for-scalability
[view call]: ../view-call