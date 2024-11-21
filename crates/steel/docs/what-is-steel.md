# What is Steel?

## Steel: Introducing Smart Contract Execution Proofs

Steel, together with the zkVM, allows developers to leverage off-chain verifiable smart contract execution. Concretely, this means carrying out EVM execution against verifiable on-chain state, within the zkVM. This will create a proof of the smart contract execution, which upon verification can be used in place of smart contract execution, while preserving on-chain security.

## On-chain vs off-chain execution

On-chain execution is limited by the gas limit per block. This is fine for simple execution, but most real-world applications require significantly more capability than what is currently available, even on layer 2 rollups. With Steel, developers can carry out the same EVM execution they would on-chain, but at a much larger scale. This EVM execution is within a boundless and verifiable environment off-chain within the zkVM, allowing for an unprecedented amount of scaling for EVM applications.

To describe how Steel replaces on-chain execution with on-chain verification of smart contract execution proofs, we will walk through a simple example: a counter variable is incremented if, and only if, the ERC20 balance of a certain account is larger than 1.

This example is purely instructive and by simplifying the execution, we can focus on understanding the specifics of Steel.

### Without Steel

```solidity
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract OnChainERC20Counter {
    address public tokenContract;
    uint256 public counter;
    
    function checkBalance(address accountAddress) public view returns (uint256) {
        return IERC20(tokenContract).balanceOf(accountAddress);
    }

    // this function will only update the counter if the account has a valid balance > 1
    function increment(address accountAddress) public {
        require(checkBalance(accountAddress) > 1, "balance must be greater than 1");
        counter += 1;
    }
}
```

The `increment` function uses the `checkBalance` function to return ERC20 the current balance of the account, and the require statement makes sure that the counter is only updated if the balance is larger than 1.

### With Steel

```solidity
contract OffChainERC20Counter() {
    address public tokenContract;
    uint256 public counter;

    // this function will only update the counter if the account has a valid balance > 1
    function increment(bytes calldata journalData, bytes calldata seal) public {
        // Decode and validate the journal data
        Journal memory journal = abi.decode(journalData, (Journal));
        require(journal.tokenContract == tokenContract, "Invalid Token Address");
        require(Steel.validateCommitment(journal.commitment), "Invalid Steel Commitment");

        // Verify the execution proof
        bytes32 journalHash = sha256(journalData);
        verifier.verify(seal, imageID, journalHash);

        counter += 1;
    }
    }
}
```

To make sure that Steel's execution proofs can be trusted, we check the output of the zkVM program to make sure that the token contract address is correct, and we validate the [Steel Commitment]. Only if these are valid, the proof is verified. Upon successful verification, we can be sure that the account balance is larger than 1 and we increment the counter variable. Notice there is no check on-chain of the balance or any EVM execution other than the validations and proof verification. The EVM execution happens within the zkVM guest program.

In [How does Steel work?], we dive deeper into how exactly the zkVM guest program verifies state access and runs EVM execution, generating a smart contract execution proof, and verifying the proof on-chain.

---

<---- [Steel README] | [How Does Steel Work?] ---->

[Steel Commitment]: ./steel-commitments.md
[How does Steel work?]: ./how-does-steel-work.md
[Steel README]: ../README.md
[How Does Steel Work]: ./how-does-steel-work.md
