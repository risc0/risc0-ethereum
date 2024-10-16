// Copyright 2024 RISC Zero, Inc.
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

use crate::optimism::OpBlockHeader;
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
pub type DisputeGameInput = ComposeInput<OpBlockHeader, DisputeGameCommit>;

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
        transports::Transport,
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

        // docker run -i ethereum/solc:0.8.27 - --optimize --bin-runtime
        #[sol(rpc, deployed_bytecode="608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063b0de44ac1461002d575b5f5ffd5b61004061003b366004610486565b610052565b60405190815260200160405180910390f35b5f8061005e83426104d1565b90505f846001600160a01b0316633c9f397c6040518163ffffffff1660e01b8152600401602060405180830381865afa15801561009d573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906100c19190610509565b90505f856001600160a01b0316634fd0434c6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610100573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101249190610529565b90505f866001600160a01b031663f2b4e6176040518163ffffffff1660e01b8152600401602060405180830381865afa158015610163573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101879190610544565b90505f816001600160a01b0316634d1975b46040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101c6573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101ea919061055f565b90505b801561043b575f80806001600160a01b03851663bb8aa1fc61020e86610576565b9550856040518263ffffffff1660e01b815260040161022f91815260200190565b606060405180830381865afa15801561024a573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061026e919061058b565b9250925092508567ffffffffffffffff168267ffffffffffffffff1610156102985750505061043b565b8663ffffffff168363ffffffff16146102b3575050506101ed565b6040516322c4269960e11b81526001600160a01b0382811660048301528c16906345884d3290602401602060405180830381865afa1580156102f7573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061031b91906105d2565b15610328575050506101ed565b6002816001600160a01b031663200d2ed26040518163ffffffff1660e01b8152600401602060405180830381865afa158015610366573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061038a9190610605565b600281111561039b5761039b6105f1565b146103a8575050506101ed565b8767ffffffffffffffff16816001600160a01b03166319effeb46040518163ffffffff1660e01b8152600401602060405180830381865afa1580156103ef573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906104139190610529565b67ffffffffffffffff16111561042b575050506101ed565b8398505050505050505050610454565b6040516309b3c62760e21b815260040160405180910390fd5b92915050565b6001600160a01b038116811461046e575f5ffd5b50565b67ffffffffffffffff8116811461046e575f5ffd5b5f5f60408385031215610497575f5ffd5b82356104a28161045a565b915060208301356104b281610471565b809150509250929050565b634e487b7160e01b5f52601160045260245ffd5b67ffffffffffffffff8281168282160390811115610454576104546104bd565b805163ffffffff81168114610504575f5ffd5b919050565b5f60208284031215610519575f5ffd5b610522826104f1565b9392505050565b5f60208284031215610539575f5ffd5b815161052281610471565b5f60208284031215610554575f5ffd5b81516105228161045a565b5f6020828403121561056f575f5ffd5b5051919050565b5f81610584576105846104bd565b505f190190565b5f5f5f6060848603121561059d575f5ffd5b6105a6846104f1565b925060208401516105b681610471565b60408501519092506105c78161045a565b809150509250925092565b5f602082840312156105e2575f5ffd5b81518015158114610522575f5ffd5b634e487b7160e01b5f52602160045260245ffd5b5f60208284031215610615575f5ffd5b815160038110610522575f5ffdfea264697066735822122089257296e00cbc25ff86fc972511974b0cfb06b0be6abdeec67857f760a9ca4064736f6c634300081b0033")]
        contract OPGameFinder {
            error GameNotFound();

            /// @notice Finds the index of the latest finalized OP  dispute game.
            ///
            /// This function iterates through all games created by the DisputeGameFactory and finds one that meets certain criteria:
            /// - Was created after respectedGameTypeUpdatedAt
            /// - Has the same respected game type as IOptimismPortal2's current respected game type
            /// - Is not blacklisted on IOptimismPortal2
            /// - Resolved in favor of the root claim (the output proposal) and has been resolved for at least `delay` seconds.
            ///
            /// @param portal The address of an instance of Optimism Portal 2 contract
            /// @param delay Time period to wait before considering a game finalized, measured from block timestamp
            ///
            /// @return uint256 Finalized index if found; reverts with GameNotFound error otherwise
            function findFinalizedIndex(address portal, uint64 delay) external view returns (uint256) {
                uint64 ts = uint64(block.timestamp) - delay;
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
                    // The game must not be blacklisted.
                    if (IOptimismPortal2(portal).disputeGameBlacklist(game)) continue;
                    // The game must be resolved in favor of the root claim (the output proposal).
                    if (IDisputeGame(game).status() != GameStatus.DEFENDER_WINS) continue;
                    // The game must have been resolved for at least `delay` seconds.
                    if (IDisputeGame(game).resolvedAt() > ts) continue;

                    return i;
                }

                revert GameNotFound();
            }
        }
    }

    impl OutputRootProof {
        async fn from_provider<T, P2>(
            provider: P2,
            block_number: BlockNumber,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            P2: Provider<T, Optimism>,
        {
            let block_response = provider
                .get_block_by_number(block_number.into(), false)
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
        /// The latest feasible fault dispute game that has been resolved for this many seconds.
        Finalized(u64),
    }

    #[derive(Clone, Debug)]
    pub struct DisputeGame {
        pub index: U256,
        pub l2_block_number: BlockNumber,
        pub output_root_proof: OutputRootProof,
    }

    #[derive(Clone, Debug)]
    pub struct OptimismPortal2<T, P>(IOptimismPortal2Instance<T, P>);

    impl<T, P1> OptimismPortal2<T, P1>
    where
        T: Transport + Clone,
        P1: Provider<T, Ethereum>,
    {
        pub const fn new(address: Address, provider: P1) -> Self {
            Self(IOptimismPortal2Instance::new(address, provider))
        }

        pub async fn dispute_game<P2: Provider<T, Optimism>>(
            &self,
            index: DisputeGameIndex,
            l2_provider: P2,
        ) -> anyhow::Result<DisputeGame> {
            let game_type = self.0.respectedGameType().call().await?._0;
            let updated_at = self.0.respectedGameTypeUpdatedAt().call().await?._0;
            let factory_address = self.0.disputeGameFactory().call().await?._0;
            let factory = IDisputeGameFactory::new(factory_address, self.0.provider());

            match index {
                DisputeGameIndex::Latest => {
                    find_latest_game(l2_provider, game_type, updated_at, factory, None).await
                }
                DisputeGameIndex::Finalized(delay) => {
                    // Finding the latest finalized game is very RPC intensive, instead we use the
                    // OPGameFinder contract to get it in one call. To ensure that this contract is
                    // always available, we override the state of the null address.
                    let finder = OPGameFinder::new(Address::ZERO, self.0.provider());
                    let mut overrides = StateOverride::default();
                    overrides.insert(
                        *finder.address(),
                        AccountOverride {
                            code: Some(OPGameFinder::DEPLOYED_BYTECODE.clone()),
                            ..Default::default()
                        },
                    );
                    let index = finder
                        .findFinalizedIndex(*self.0.address(), delay)
                        .call()
                        .overrides(&overrides)
                        .await?
                        ._0;
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

    async fn find_latest_game<T, P1, P2>(
        l2_provider: P2,
        game_type: u32,
        game_type_updated_at: u64,
        factory: IDisputeGameFactoryInstance<T, P1>,
        start_index: Option<U256>,
    ) -> anyhow::Result<DisputeGame>
    where
        T: Transport + Clone,
        P1: Provider<T, Ethereum>,
        P2: Provider<T, Optimism>,
    {
        let index = match start_index {
            Some(index) => index,
            None => {
                let game_count = factory.gameCount().call().await?.gameCount;
                game_count - uint!(1U256)
            }
        };
        let games = factory
            .findLatestGames(game_type, index, DISPUTE_GAME_FETCH_COUNT)
            .call()
            .await?
            .games;

        for game in games {
            if game.createdAt < game_type_updated_at {
                break;
            }
            // the extra data should contain the block number
            let Ok(l2_block_number) = u64::abi_decode(&game.extraData, true) else {
                continue;
            };
            // verify the claim of the game
            let output_root_proof = OutputRootProof::from_provider(&l2_provider, l2_block_number)
                .await
                .context("failed to construct output root")?;
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
