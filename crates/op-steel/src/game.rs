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
        // https://github.com/ethereum-optimism/optimism/blob/v1.9.3/packages/contracts-bedrock/src/L1/interfaces/IOptimismPortal2.sol
        #[sol(rpc)]
        interface IOptimismPortal2 {
            function disputeGameBlacklist(address) external view returns (bool);
            function disputeGameFactory() external view returns (address);
            function proofMaturityDelaySeconds() external view returns (uint256);
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

        // https://github.com/ethereum-optimism/optimism/blob/v1.9.3/packages/contracts-bedrock/src/dispute/interfaces/IDisputeGame.sol
        interface IDisputeGame {
            function status() external view returns (GameStatus);
            function resolvedAt() external view returns (uint64);
        }

        // https://github.com/ethereum-optimism/optimism/blob/v1.9.3/packages/contracts-bedrock/src/dispute/lib/Types.sol
        enum GameStatus {
            IN_PROGRESS,
            CHALLENGER_WINS,
            DEFENDER_WINS
        }

        // docker run -i ethereum/solc:0.8.28 - --optimize --bin-runtime
        #[sol(rpc, deployed_bytecode="608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063e2ead3881461002d575b5f5ffd5b61004061003b3660046104bf565b610052565b60405190815260200160405180910390f35b5f5f826001600160a01b031663bf653a5c6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610090573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906100b491906104e1565b6100be904261050c565b90505f836001600160a01b0316633c9f397c6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100fd573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610121919061053d565b90505f846001600160a01b0316634fd0434c6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610160573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610184919061056d565b90505f856001600160a01b031663f2b4e6176040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101c3573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101e79190610586565b90505f816001600160a01b0316634d1975b46040518163ffffffff1660e01b8152600401602060405180830381865afa158015610226573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061024a91906104e1565b90505b801561048f575f80806001600160a01b03851663bb8aa1fc61026e866105a1565b9550856040518263ffffffff1660e01b815260040161028f91815260200190565b606060405180830381865afa1580156102aa573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906102ce91906105b6565b9250925092508567ffffffffffffffff168267ffffffffffffffff1610156102f85750505061048f565b8663ffffffff168363ffffffff16146103135750505061024d565b6002816001600160a01b031663200d2ed26040518163ffffffff1660e01b8152600401602060405180830381865afa158015610351573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610375919061060e565b6002811115610386576103866105fa565b146103935750505061024d565b87816001600160a01b03166319effeb46040518163ffffffff1660e01b8152600401602060405180830381865afa1580156103d0573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906103f4919061056d565b67ffffffffffffffff16111561040c5750505061024d565b6040516322c4269960e11b81526001600160a01b0382811660048301528b16906345884d3290602401602060405180830381865afa158015610450573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610474919061062c565b156104815750505061024d565b509198975050505050505050565b6040516309b3c62760e21b815260040160405180910390fd5b6001600160a01b03811681146104bc575f5ffd5b50565b5f602082840312156104cf575f5ffd5b81356104da816104a8565b9392505050565b5f602082840312156104f1575f5ffd5b5051919050565b634e487b7160e01b5f52601160045260245ffd5b8181038181111561051f5761051f6104f8565b92915050565b805163ffffffff81168114610538575f5ffd5b919050565b5f6020828403121561054d575f5ffd5b6104da82610525565b805167ffffffffffffffff81168114610538575f5ffd5b5f6020828403121561057d575f5ffd5b6104da82610556565b5f60208284031215610596575f5ffd5b81516104da816104a8565b5f816105af576105af6104f8565b505f190190565b5f5f5f606084860312156105c8575f5ffd5b6105d184610525565b92506105df60208501610556565b915060408401516105ef816104a8565b809150509250925092565b634e487b7160e01b5f52602160045260245ffd5b5f6020828403121561061e575f5ffd5b8151600381106104da575f5ffd5b5f6020828403121561063c575f5ffd5b815180151581146104da575f5ffdfea2646970667358221220caaf151e3bd0c01c54728b1bd0c20b5bc683a713c7d064892cdde24968be9a3e64736f6c634300081c0033")]
        contract OPGameFinder {
            error GameNotFound();

            /// @notice Finds the index of the latest finalized OP dispute game.
            ///
            /// This function iterates through all games created by the DisputeGameFactory and finds one that meets certain criteria:
            /// - Was created after respectedGameTypeUpdatedAt
            /// - Has the same respected game type as IOptimismPortal2's current respected game type
            /// - Resolved in favor of the root claim (the output proposal)
            /// - Has been resolved for at least IOptimismPortal2's proof maturity delay seconds
            /// - Is not blacklisted on IOptimismPortal2
            ///
            /// @param portal The address of an instance of Optimism Portal 2 contract
            ///
            /// @return uint256 Finalized index if found; reverts with GameNotFound error otherwise
            function findFinalizedIndex(address portal) external view returns (uint256) {
                uint256 ts = block.timestamp - IOptimismPortal2(portal).proofMaturityDelaySeconds();
                uint32 respectedGameType = IOptimismPortal2(portal).respectedGameType();
                uint64 respectedGameTypeUpdatedAt = IOptimismPortal2(portal).respectedGameTypeUpdatedAt();
                IDisputeGameFactory factory = IDisputeGameFactory(IOptimismPortal2(portal).disputeGameFactory());
                uint256 i = factory.gameCount();
                while (i > 0) {
                    // Fetch the dispute game proxy from the `DisputeGameFactory` contract.
                    (uint32 gameType, uint64 createdAt, address game) = factory.gameAtIndex(--i);
                    // The game must have been created after `respectedGameTypeUpdatedAt`.
                    if (createdAt < respectedGameTypeUpdatedAt) break;
                    // The game type of the dispute game must be the respected game type.
                    if (gameType != respectedGameType) continue;
                    // The game must be resolved in favor of the root claim (the output proposal).
                    if (IDisputeGame(game).status() != GameStatus.DEFENDER_WINS) continue;
                    // The game must have been resolved for at least `proofMaturityDelaySeconds`.
                    if (IDisputeGame(game).resolvedAt() > ts) continue;
                    // The game must not be blacklisted.
                    if (IOptimismPortal2(portal).disputeGameBlacklist(game)) continue;

                    return i;
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
                block_response.with_context(|| format!("block not found: {}", block_number))?;
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
                    let index = finder
                        .findFinalizedIndex(*self.0.address())
                        .call()
                        .overrides(overrides)
                        .await?;
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
