use crate::optimism::OpBlockHeader;
use alloy_primitives::{keccak256, Sealed, B256};
use alloy_sol_types::SolValue;
use risc0_steel::{BlockHeaderCommit, Commitment, ComposeInput};
use serde::{Deserialize, Serialize};

alloy_sol_types::sol! {
    #![sol(all_derives)]
    #[derive(Serialize, Deserialize)]
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
    fn commit(self, header: &Sealed<OpBlockHeader>) -> Commitment {
        assert_eq!(
            self.proof.latestBlockhash,
            header.seal(),
            "Block hash mismatch"
        );
        Commitment::new(0x100, self.game_index, self.proof.hash())
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
        #[sol(rpc)]
        interface IOptimismPortal2 {
            function disputeGameFactory() external view returns (address);
            function respectedGameType() external view returns (uint32);
            function respectedGameTypeUpdatedAt() external view returns (uint64);
        }

        // https://github.com/ethereum-optimism/optimism/blob/v1.9.2/packages/contracts-bedrock/src/dispute/interfaces/IDisputeGameFactory.sol
        #[sol(rpc)]
        interface IDisputeGameFactory {
            function gameCount() external view returns (uint256);
            function gameAtIndex(uint256 index) external view returns (uint32 gameType, uint64 createdAt, address gameProxy);
            function findLatestGames(uint32 gameType, uint256 start, uint256 n) external view returns (GameSearchResult[] memory games);
        }

        // https://github.com/ethereum-optimism/optimism/blob/v1.9.2/packages/contracts-bedrock/src/dispute/interfaces/IDisputeGame.sol
        interface IDisputeGame {
            function status() external view returns (uint256);
            function resolvedAt() external view returns (uint64);
        }

        struct GameSearchResult {
            uint256 index;
            bytes32 metadata;
            uint64 createdAt;
            bytes32 rootClaim;
            bytes extraData;
        }

        uint256 constant DEFENDER_WINS = 2;

        // docker run -i ethereum/solc:0.8.27 - --evm-version paris --optimize --bin-runtime
        #[sol(rpc, deployed_bytecode="608060405234801561001057600080fd5b506004361061002b5760003560e01c8063b0de44ac14610030575b600080fd5b61004361003e366004610419565b610055565b60405190815260200160405180910390f35b6000806100628342610468565b90506000846001600160a01b0316633c9f397c6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100a4573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100c891906104a1565b90506000856001600160a01b0316634fd0434c6040518163ffffffff1660e01b8152600401602060405180830381865afa15801561010a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061012e91906104c3565b90506000866001600160a01b031663f2b4e6176040518163ffffffff1660e01b8152600401602060405180830381865afa158015610170573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061019491906104e0565b90506000816001600160a01b0316634d1975b46040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101d6573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101fa91906104fd565b90505b80156103cc57600080806001600160a01b03851663bb8aa1fc61021f86610516565b9550856040518263ffffffff1660e01b815260040161024091815260200190565b606060405180830381865afa15801561025d573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610281919061052d565b9250925092508663ffffffff168363ffffffff16146102a2575050506101fd565b8567ffffffffffffffff168267ffffffffffffffff1610156102c6575050506103cc565b6002816001600160a01b031663200d2ed26040518163ffffffff1660e01b8152600401602060405180830381865afa158015610306573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061032a91906104fd565b14610337575050506101fd565b8767ffffffffffffffff16816001600160a01b03166319effeb46040518163ffffffff1660e01b8152600401602060405180830381865afa158015610380573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906103a491906104c3565b67ffffffffffffffff1611156103bc575050506101fd565b83985050505050505050506103e5565b6040516309b3c62760e21b815260040160405180910390fd5b92915050565b6001600160a01b038116811461040057600080fd5b50565b67ffffffffffffffff8116811461040057600080fd5b6000806040838503121561042c57600080fd5b8235610437816103eb565b9150602083013561044781610403565b809150509250929050565b634e487b7160e01b600052601160045260246000fd5b67ffffffffffffffff82811682821603908111156103e5576103e5610452565b805163ffffffff8116811461049c57600080fd5b919050565b6000602082840312156104b357600080fd5b6104bc82610488565b9392505050565b6000602082840312156104d557600080fd5b81516104bc81610403565b6000602082840312156104f257600080fd5b81516104bc816103eb565b60006020828403121561050f57600080fd5b5051919050565b60008161052557610525610452565b506000190190565b60008060006060848603121561054257600080fd5b61054b84610488565b9250602084015161055b81610403565b604085015190925061056c816103eb565b80915050925092509256fea264697066735822122022c3a3c9c1cb46a163fbc2174ceb8ba0dcefeaaf471e8061a82082b2c1b50a4d64736f6c634300081b0033")]
        contract OPGameFinder {
            error GameNotFound();

            function findFinalizedIndex(address portal, uint64 delay) external view returns (uint256) {
                uint64 ts = uint64(block.timestamp) - delay;
                uint32 respectedGameType = IOptimismPortal2(portal).respectedGameType();
                uint64 respectedGameTypeUpdatedAt = IOptimismPortal2(portal).respectedGameTypeUpdatedAt();
                IDisputeGameFactory factory = IDisputeGameFactory(IOptimismPortal2(portal).disputeGameFactory());
                uint256 i = factory.gameCount();
                while (i > 0) {
                    (uint32 gameType, uint64 createdAt, address game) = factory.gameAtIndex(--i);
                    if (gameType != respectedGameType) continue; // wrong type
                    if (createdAt < respectedGameTypeUpdatedAt) break; // old game type
                    if (IDisputeGame(game).status() != DEFENDER_WINS) continue; // not resolved
                    if (IDisputeGame(game).resolvedAt() > ts) continue; // not visible
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
                .await?;
            let block =
                block_response.with_context(|| format!("block not found: {}", block_number))?;
            let header = block.header;

            let proof = provider
                .get_proof(MESSAGE_PASSER_ADDRESS, vec![])
                .hash(header.hash)
                .await?;

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
        /// The latest feasible fault dispute game that was finalized with the given delay.
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
                    let index = finder
                        .findFinalizedIndex(*self.0.address(), delay)
                        .call()
                        .overrides(&StateOverride::from([(
                            *finder.address(),
                            AccountOverride {
                                code: Some(OPGameFinder::DEPLOYED_BYTECODE.clone()),
                                ..Default::default()
                            },
                        )]))
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
                let game_count = factory.gameCount().call().await?._0;
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
            let output_root_proof =
                OutputRootProof::from_provider(&l2_provider, l2_block_number).await?;
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
