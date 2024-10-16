# Steel Commitments

Steel retrieves state for a view call at a specific block, therefore it commits the relevant block data to the journal for validation on-chain; this data is known as a Steel commitment.

Concretely, a Steel commitment consists of a block identifier, and the block hash. To validate this block commitment on-chain, the block hash in the commitment is compared with the block hash available on-chain. If there is a discrepancy, there is no guarantee that the proof accurately reflects the correct blockchain state at the specified block.

## Steel's Trust Anchor: The Blockhash

Steel uses [revm] to generate an EVM execution environment, `EvmEnv` within the guest. When you create the `EvmEnv`, you can specify a block (the default is the latest block).

```rust
// Create an EVM environment from that provider 
let mut env = EthEvmEnv::builder()
    .provider(provider.clone())
    .block_number(20842508)
    .build()
    .await?;
```

This block is used for RPC queries (i.e. `getStorageAt`) during the `preflight` call. Once the preflighting is done, `into_input` is called:

```rust
let evm_input = env.into_input().await?
```

During this `into_input` step, the preflight data is packed into a form that can be read and validated in the guest.

Crucially, during the step, Steel will use the RPC call [eth\_getProof] for all accounts accessed during the preflight and the return data is combined into a sparse Merkle trie.

Within the guest, calling `into_env` checks that all Merkle tries are consistent, have the correct root and **computes the corresponding block hash.**

_This blockhash is Steel's trust anchor; it needs to be recomputed within the guest to validate the integrity of the RPC data._

```rust
// Read the input from the guest environment.
let input: EthEvmInput = env::read();
let contract: Address = env::read();
let account: Address = env::read();

// Converts the input into a `EvmEnv`
let env = input.into_env().with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
```

For the Steel commitment, it is this block hash, computed within the guest, that is committed to the journal:

```rust
let journal = Journal {
    commitment: env.into_commitment(),
    tokenAddress: contract,
};
env::commit_slice(&journal.abi_encode());
```

This block hash has to be compared on-chain, alongside the verification of the proof, to validate that the Steel proof is correct and to verify the integrity of RPC data.

## What is a Steel Commitment?

A commitment consists of two values: the block ID and the block digest. The block ID encodes two values, the Steel version number and a block identifier (e.g. a block number).

```solidity
struct Commitment {
    uint256 id;
    bytes32 digest;
    bytes32 configID
}
```

In the `increment` function in the `Counter` contract, we saw this require statement:

```solidity
require(Steel.validateCommitment(journal.commitment), "Invalid commitment");
```

The [Steel library](https://github.com/risc0/risc0-ethereum/blob/main/contracts/src/steel/Steel.sol) contains the function `validateCommitment` :

```solidity
function validateCommitment(Commitment memory commitment) internal view returns (bool) {
    (uint240 claimID, uint16 version) = Encoding.decodeVersionedID(commitment.id);
    if (version == 0) {
        return validateBlockCommitment(claimID, commitment.digest);
    } else if (version == 1) {
        return validateBeaconCommitment(claimID, commitment.digest);
    } else {
        revert InvalidCommitmentVersion();
    }
}
```

## Validation of Steel Commitments

Steel supports two methods of commitment validation (see `validateCommitment` in [Steel.sol]); This validation on-chain is essential to ensure that the proof accurately reflects the correct blockchain state.

1. Block hash commitment

```solidity
/// @notice Validates if the provided block commitment matches the block hash of the given block number.
/// @param blockNumber The block number to compare against.
/// @param blockHash The block hash to validate.
/// @return True if the block's block hash matches the block hash, false otherwise.
function validateBlockCommitment(uint256 blockNumber, bytes32 blockHash) internal view returns (bool) {
    if (block.number - blockNumber > 256) {
        revert CommitmentTooOld();
    }
    return blockHash == blockhash(blockNumber);
}
```

This method uses the `blockhash` opcode to commit to a block hash that is no more than 256 blocks old. With Ethereum's 12-second block time, this provides a window of about 50 minutes to generate the proof and ensure that the validating transaction is contained in a block. This approach will work for most scenarios, including complex computations, as it typically provides sufficient time to generate the proof.

2. Beacon Block Root Commitment

```solidity
/// @notice Validates if the provided beacon commitment matches the block root of the given timestamp.
/// @param timestamp The timestamp to compare against.
/// @param blockRoot The block root to validate.
/// @return True if the block's block root matches the block root, false otherwise.
function validateBeaconCommitment(uint256 timestamp, bytes32 blockRoot) internal view returns (bool) {
    if (block.timestamp - timestamp > 12 * 8191) {
        revert CommitmentTooOld();
    }
    return blockRoot == Beacon.parentBlockRoot(timestamp);
}
```

The second method allows validation using the [EIP-4788] beacon roots contract. This technique extends the time window in which the proof can be validated on-chain to just over a day. It requires access to a beacon API endpoint and can be enabled by calling `EvmEnv::builder().beacon_api()`. However, this approach is specific to Ethereum (L1) Steel proofs and depends on the implementation of EIP-4788.

Note that EIP-4788 only provides access to the parent beacon root, requiring iterative queries in Solidity to retrieve the target beacon root for validation. This iterative process can result in slightly higher gas costs compared to using the `blockhash` opcode. Overall, it is suitable for environments where longer proof generation times are required.

---

<----[How Does Steel Work?](./how-does-steel-work.md) | [Steel README](../README.md) ---->

[revm]: https://docs.rs/revm/latest/revm/
[eth_getProof]: https://docs.alchemy.com/reference/eth-getproof
[Steel library]: https://github.com/risc0/risc0-ethereum/blob/main/contracts/src/steel/Steel.sol
[Steel.sol]: https://github.com/risc0/risc0-ethereum/blob/main/contracts/src/steel/Steel.sol
[EIP-4788]: https://eips.ethereum.org/EIPS/eip-4788
[How Does Steel Work?]: ./how-does-steel-work.md
[Steel README]: ../README.md
