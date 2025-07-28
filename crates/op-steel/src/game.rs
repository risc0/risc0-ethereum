// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::optimism::{OpBlockHeader, OpEvmFactory};
use alloy_primitives::{keccak256, Sealed, B256};
use alloy_sol_types::SolValue;
use risc0_steel::{BlockHeaderCommit, Commitment, ComposeInput};
use serde::{Deserialize, Serialize};

alloy_sol_types::sol! {
    // https://github.com/ethereum-optimism/optimism/blob/v1.9.3/packages/contracts-bedrock/src/libraries/Types.sol
    #![sol(all_derives)]
    #[derive(Serialize, Deserialize)]
    /// @notice Struct representing the elements that are hashed together to generate an output root
    ///         which itself represents a snapshot of the L2 state.
    /// @custom:field version                  Version of the output root.
    /// @custom:field stateRoot                Root of the state trie at the block of this output.
    /// @custom:field messagePasserStorageRoot Root of the message passer storage trie.
    /// @custom:field latestBlockhash          Hash of the block this output was generated from.
    struct OutputRootProof {
        bytes32 version;
        bytes32 stateRoot;
        bytes32 messagePasserStorageRoot;
        bytes32 latestBlockhash;
    }
}

impl OutputRootProof {
    #[inline]
    pub fn hash(&self) -> B256 {
        keccak256(self.abi_encode())
    }
}

/// Input committing to the root claim of an OP dispute game.
pub type DisputeGameInput = ComposeInput<OpEvmFactory, DisputeGameCommit>;

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeGameCommit {
    game_index: u64,
    proof: OutputRootProof,
}

impl DisputeGameCommit {
    pub const fn new(game_index: u64, proof: OutputRootProof) -> Self {
        Self { game_index, proof }
    }
}

impl BlockHeaderCommit<OpBlockHeader> for DisputeGameCommit {
    #[inline]
    fn commit(self, header: &Sealed<OpBlockHeader>, config_id: B256) -> Commitment {
        assert_eq!(
            self.proof.latestBlockhash,
            header.seal(),
            "Block hash mismatch"
        );
        Commitment::new(0x100, self.game_index, self.proof.hash(), config_id)
    }
}

#[cfg(feature = "host")]
pub mod host {
    use super::*;
    use alloy::{
        network::Ethereum,
        providers::Provider,
        rpc::types::state::{AccountOverride, StateOverride},
    };
    use alloy_primitives::{address, uint, Address, BlockNumber, B256, U256};
    use anyhow::{bail, ensure, Context};
    use op_alloy_network::Optimism;
    use IDisputeGameFactory::IDisputeGameFactoryInstance;
    use IOptimismPortal2::IOptimismPortal2Instance;

    /// Address of the L2ToL1MessagePasser contract.
    const MESSAGE_PASSER_ADDRESS: Address = address!("4200000000000000000000000000000000000016");
    const DISPUTE_GAME_FETCH_COUNT: U256 = uint!(20_U256);

    alloy::sol! {
        // https://github.com/ethereum-optimism/optimism/blob/v1.13.5/packages/contracts-bedrock/interfaces/L1/IOptimismPortal2.sol
        #[sol(rpc)]
        interface IOptimismPortal2 {
            function anchorStateRegistry() external view returns (address);
            function disputeGameFactory() external view returns (address);
            function respectedGameType() external view returns (uint32);
            function respectedGameTypeUpdatedAt() external view returns (uint64);
            function version() external pure returns (string memory);
        }

        // https://github.com/ethereum-optimism/optimism/blob/v1.9.3/packages/contracts-bedrock/src/dispute/interfaces/IDisputeGameFactory.sol
        #[sol(rpc)]
        interface IDisputeGameFactory {
            function gameCount() external view returns (uint256 gameCount);
            function gameAtIndex(uint256 index) external view returns (uint32 gameType, uint64 createdAt, address gameProxy);
            function findLatestGames(uint32 gameType, uint256 start, uint256 n) external view returns (GameSearchResult[] memory games);
        }

        struct GameSearchResult {
            uint256 index;
            bytes32 metadata;
            uint64 createdAt;
            bytes32 rootClaim;
            bytes extraData;
        }

        // https://github.com/ethereum-optimism/optimism/blob/v1.13.5/packages/contracts-bedrock/interfaces/dispute/IAnchorStateRegistry.sol
        interface IAnchorStateRegistry {
            function isGameClaimValid(address) external view returns (bool);
        }

        // docker run -i ethereum/solc:0.8.28 - --optimize --bin-runtime
        #[sol(rpc, deployed_bytecode="608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063e2ead3881461002d575b5f5ffd5b61004061003b3660046102ae565b610052565b60405190815260200160405180910390f35b5f5f826001600160a01b031663f2b4e6176040518163ffffffff1660e01b8152600401602060405180830381865afa158015610090573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906100b491906102d0565b90505f836001600160a01b0316635c0cba336040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100f3573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061011791906102d0565b90505f826001600160a01b0316634d1975b46040518163ffffffff1660e01b8152600401602060405180830381865afa158015610156573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061017a91906102eb565b90505b801561027e575f6001600160a01b03841663bb8aa1fc61019c84610302565b9350836040518263ffffffff1660e01b81526004016101bd91815260200190565b606060405180830381865afa1580156101d8573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101fc9190610323565b604051636c4f446760e01b81526001600160a01b0380831660048301529194509086169250636c4f44679150602401602060405180830381865afa158015610246573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061026a9190610381565b156102785750949350505050565b5061017d565b6040516309b3c62760e21b815260040160405180910390fd5b6001600160a01b03811681146102ab575f5ffd5b50565b5f602082840312156102be575f5ffd5b81356102c981610297565b9392505050565b5f602082840312156102e0575f5ffd5b81516102c981610297565b5f602082840312156102fb575f5ffd5b5051919050565b5f8161031c57634e487b7160e01b5f52601160045260245ffd5b505f190190565b5f5f5f60608486031215610335575f5ffd5b835163ffffffff81168114610348575f5ffd5b602085015190935067ffffffffffffffff81168114610365575f5ffd5b604085015190925061037681610297565b809150509250925092565b5f60208284031215610391575f5ffd5b815180151581146102c9575f5ffdfea2646970667358221220ece184f96e1fb64eaf9e4e9eca74f8f0ffe3d70623a843d6cd252d7f6450938e64736f6c634300081c0033")]
        contract OPGameFinder {
            error GameNotFound();

            /// @notice Finds the index of the latest finalized OP dispute game.
            ///
            /// This function iterates through all games created by the DisputeGameFactory and finds
            /// the latest game with a valid root claim.
            ///
            /// @param portal The address of an instance of Optimism Portal 2 contract
            ///
            /// @return uint256 Finalized index if found; reverts with GameNotFound error otherwise
            function findFinalizedIndex(address portal) external view returns (uint256) {
                IDisputeGameFactory factory = IDisputeGameFactory(IOptimismPortal2(portal).disputeGameFactory());
                IAnchorStateRegistry anchorStateRegistry = IAnchorStateRegistry(IOptimismPortal2(portal).anchorStateRegistry());

                uint256 i = factory.gameCount();
                while (i > 0) {
                    // Fetch the dispute game proxy from the `DisputeGameFactory` contract.
                    (, , address game) = factory.gameAtIndex(--i);

                    // Check that the root claim is valid.
                    if (anchorStateRegistry.isGameClaimValid(game)) {
                        return i;
                    }
                }

                revert GameNotFound();
            }
        }
    }

    impl OutputRootProof {
        async fn from_provider<P2>(provider: P2, block_number: BlockNumber) -> anyhow::Result<Self>
        where
            P2: Provider<Optimism>,
        {
            let block_response = provider
                .get_block_by_number(block_number.into())
                .hashes()
                .await
                .context("eth_getBlockByNumber failed")?;
            let block =
                block_response.with_context(|| format!("block not found: {block_number}"))?;
            let header = block.header;

            let proof = provider
                .get_proof(MESSAGE_PASSER_ADDRESS, vec![])
                .hash(header.hash)
                .await
                .with_context(|| format!("eth_getProof failed for block {}", header.hash))?;

            Ok(Self {
                version: B256::ZERO,
                stateRoot: header.state_root,
                messagePasserStorageRoot: proof.storage_hash,
                latestBlockhash: header.hash,
            })
        }
    }

    #[derive(Clone, Debug, Default)]
    pub enum DisputeGameIndex {
        /// The latest feasible fault dispute game.
        #[default]
        Latest,
        /// The fault dispute game with the given index.
        Number(u64),
        /// The latest finalized fault dispute game.
        Finalized,
    }

    #[derive(Clone, Debug)]
    pub struct DisputeGame {
        pub index: U256,
        pub l2_block_number: BlockNumber,
        pub output_root_proof: OutputRootProof,
    }

    #[derive(Clone, Debug)]
    pub struct OptimismPortal2<P>(IOptimismPortal2Instance<P>);

    impl<P1> OptimismPortal2<P1>
    where
        P1: Provider<Ethereum>,
    {
        pub const fn new(address: Address, provider: P1) -> Self {
            Self(IOptimismPortal2Instance::new(address, provider))
        }

        pub async fn dispute_game<P2: Provider<Optimism>>(
            &self,
            index: DisputeGameIndex,
            l2_provider: P2,
        ) -> anyhow::Result<DisputeGame> {
            let game_type = self.0.respectedGameType().call().await?;
            let updated_at = self.0.respectedGameTypeUpdatedAt().call().await?;
            let factory_address = self.0.disputeGameFactory().call().await?;
            let factory = IDisputeGameFactory::new(factory_address, self.0.provider());

            match index {
                DisputeGameIndex::Latest => {
                    find_latest_game(l2_provider, game_type, updated_at, factory, None).await
                }
                DisputeGameIndex::Finalized => {
                    // Finding the latest finalized game is very RPC intensive, instead we use the
                    // OPGameFinder contract to get it in one call. To ensure that this contract is
                    // always available, we override the code of a random address.
                    let finder = OPGameFinder::new(Address::random(), self.0.provider());
                    let mut overrides = StateOverride::default();
                    overrides.insert(
                        *finder.address(),
                        AccountOverride {
                            code: Some(OPGameFinder::DEPLOYED_BYTECODE.clone()),
                            ..Default::default()
                        },
                    );
                    let find_index = finder.findFinalizedIndex(*self.0.address());
                    let index = match find_index.call().overrides(overrides).await {
                        Ok(index) => index,
                        Err(err) => match err.as_decoded_error::<OPGameFinder::GameNotFound>() {
                            None => {
                                bail!(anyhow::Error::new(err).context("findFinalizedIndex failed"))
                            }
                            Some(_) => bail!("no valid finalized game exists"),
                        },
                    };
                    // get the actual game of this index
                    let game =
                        find_latest_game(l2_provider, game_type, updated_at, factory, Some(index))
                            .await?;
                    ensure!(
                        game.index == index,
                        "invalid dispute game at index: {}",
                        index
                    );

                    Ok(game)
                }
                DisputeGameIndex::Number(index) => {
                    let index = U256::from(index);
                    // get the actual game of this index
                    let game =
                        find_latest_game(l2_provider, game_type, updated_at, factory, Some(index))
                            .await?;
                    ensure!(
                        game.index == index,
                        "invalid dispute game at index: {}",
                        index
                    );

                    Ok(game)
                }
            }
        }
    }

    async fn find_latest_game<P1, P2>(
        l2_provider: P2,
        game_type: u32,
        game_type_updated_at: u64,
        factory: IDisputeGameFactoryInstance<P1>,
        start_index: Option<U256>,
    ) -> anyhow::Result<DisputeGame>
    where
        P1: Provider<Ethereum>,
        P2: Provider<Optimism>,
    {
        let index = match start_index {
            Some(index) => index,
            None => {
                let game_count = factory.gameCount().call().await?;
                game_count - uint!(1U256)
            }
        };
        let games = factory
            .findLatestGames(game_type, index, DISPUTE_GAME_FETCH_COUNT)
            .call()
            .await?;

        for game in games {
            if game.createdAt < game_type_updated_at {
                break;
            }
            // the extra data should contain the block number
            let Ok(l2_block_number) = u64::abi_decode(&game.extraData) else {
                continue;
            };
            // verify the claim of the game
            let output_root_proof = OutputRootProof::from_provider(&l2_provider, l2_block_number)
                .await
                .with_context(|| {
                    format!("failed to create OutputRootProof for game {}", game.index)
                })?;
            if game.rootClaim == output_root_proof.hash() {
                return Ok(DisputeGame {
                    index: game.index,
                    l2_block_number,
                    output_root_proof,
                });
            }
        }

        bail!(
            "no valid dispute games in range: {:?}",
            index - DISPUTE_GAME_FETCH_COUNT..=index
        )
    }
}
