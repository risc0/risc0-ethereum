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

use crate::{
    beacon, BeaconCommit, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput,
    EvmBlockHeader, MerkleTrie,
};
use alloy_primitives::{b256, keccak256, Sealed, B256, U256};
use beacon::{GeneralizedBeaconCommit, STATE_ROOT_LEAF_INDEX};
use beacon_roots::BeaconRootsContract;
use serde::{Deserialize, Serialize};

pub type HistoryInput<H> = ComposeInput<H, HistoryCommit>;

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryCommit {
    /// Commit for the Steel EVM execution to a beacon block hash.
    evm_commit: BeaconCommit,
    /// State for verifying `evm_commit`.
    state: beacon_roots::State,
    /// Commitment for `state` to a beacon block hash.
    state_commit: GeneralizedBeaconCommit<STATE_ROOT_LEAF_INDEX>,
}

impl<H: EvmBlockHeader> BlockHeaderCommit<H> for HistoryCommit {
    fn commit(self, header: &Sealed<H>) -> Commitment {
        let commitment = self.evm_commit.commit(header);
        let (timestamp, version) = Commitment::decode_id(commitment.blockID);
        assert_eq!(version, CommitmentVersion::Beacon as u16);

        let state_root = self.state.root();
        let commitment_root = BeaconRootsContract::new(self.state).get(timestamp);
        assert_eq!(commitment_root, commitment.blockDigest);

        let (timestamp, beacon_root) = self.state_commit.into_commit(state_root);

        Commitment::new(CommitmentVersion::Beacon as u16, timestamp, beacon_root)
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::{
        beacon::{
            host::{client::BeaconClient, create_beacon_commit},
            STATE_ROOT_LEAF_INDEX,
        },
        ethereum::EthBlockHeader,
    };
    use alloy::{network::Ethereum, providers::Provider, transports::Transport};
    use anyhow::Context;
    use url::Url;

    impl HistoryCommit {
        pub(crate) async fn from_beacon_commit_and_header<T, P>(
            evm_commit: BeaconCommit,
            commit_header: &Sealed<EthBlockHeader>,
            rpc_provider: P,
            beacon_url: Url,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            P: Provider<T, Ethereum>,
        {
            let (_, timestamp) = evm_commit.clone().into_parts();
            let (_, state) = BeaconRootsContract::preflight_get(
                U256::from(timestamp),
                &rpc_provider,
                commit_header.seal().into(),
            )
            .await?;

            let client = BeaconClient::new(beacon_url).context("invalid URL")?;
            let (proof, timestamp, beacon_root) =
                create_beacon_commit(commit_header, "state_root".into(), &rpc_provider, &client)
                    .await?;
            let state_commit =
                GeneralizedBeaconCommit::<STATE_ROOT_LEAF_INDEX>::new(proof, timestamp);
            state_commit
                .verify(state.root(), beacon_root)
                .context("proof derived from API does not verify")?;

            log::info!(
                "Committing to parent beacon block: root={},timestamp={}",
                beacon_root,
                timestamp
            );

            Ok(HistoryCommit {
                evm_commit,
                state,
                state_commit,
            })
        }
    }
}

mod beacon_roots {
    use super::*;
    use crate::StateAccount;
    use alloy_primitives::uint;

    #[derive(Clone, Serialize, Deserialize)]
    pub struct State {
        pub state_trie: MerkleTrie,
        pub storage_trie: MerkleTrie,
    }

    impl State {
        #[inline]
        pub fn root(&self) -> B256 {
            self.state_trie.hash_slow()
        }
    }

    pub struct BeaconRootsContract {
        storage: MerkleTrie,
    }

    impl BeaconRootsContract {
        pub const HISTORY_BUFFER_LENGTH: U256 = uint!(8191_U256);

        /// keccak256(address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02"))
        const ADDRESS_HASH: B256 =
            b256!("37d65eaa92c6bc4c13a5ec45527f0c18ea8932588728769ec7aecfe6d9f32e42");
        const CODE_HASH: B256 =
            b256!("f57acd40259872606d76197ef052f3d35588dadf919ee1f0e3cb9b62d3f4b02c");

        pub fn new(state: State) -> Self {
            let account: StateAccount = state
                .state_trie
                .get_rlp(Self::ADDRESS_HASH)
                .expect("Invalid encoded state trie value")
                .unwrap_or_default();
            assert_eq!(account.code_hash, Self::CODE_HASH, "Invalid code hash");
            assert_eq!(state.storage_trie.hash_slow(), account.storage_root);

            Self {
                storage: state.storage_trie,
            }
        }

        pub fn get(&self, calldata: U256) -> B256 {
            assert!(!calldata.is_zero());

            let timestamp_idx = calldata % Self::HISTORY_BUFFER_LENGTH;
            let timestamp = self.storage_get(timestamp_idx);
            assert_eq!(timestamp, calldata);

            let root_idx = timestamp_idx + Self::HISTORY_BUFFER_LENGTH;
            let root = self.storage_get(root_idx);

            root.into()
        }

        fn storage_get(&self, index: U256) -> U256 {
            self.storage
                .get_rlp(keccak256(index.to_be_bytes::<32>()))
                .expect("Invalid encoded storage value")
                .unwrap_or_default()
        }

        #[cfg(feature = "host")]
        pub async fn preflight_get<T, N, P>(
            calldata: U256,
            provider: P,
            block_id: alloy::eips::BlockId,
        ) -> anyhow::Result<(B256, State)>
        where
            T: alloy::transports::Transport + Clone,
            N: alloy::network::Network,
            P: alloy::providers::Provider<T, N>,
        {
            const ADDRESS: alloy_primitives::Address =
                alloy_primitives::address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

            let timestamp_idx = calldata % Self::HISTORY_BUFFER_LENGTH;
            let root_idx = timestamp_idx + Self::HISTORY_BUFFER_LENGTH;

            let proof = provider
                .get_proof(ADDRESS, vec![timestamp_idx.into(), root_idx.into()])
                .block_id(block_id)
                .await?;
            let state = State {
                state_trie: MerkleTrie::from_rlp_nodes(proof.account_proof)?,
                storage_trie: MerkleTrie::from_rlp_nodes(
                    proof.storage_proof.iter().flat_map(|p| &p.proof),
                )?,
            };
            let returns = Self::new(state.clone()).get(calldata);

            Ok((returns, state))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ethereum::EthEvmEnv, host::BlockNumberOrTag, Contract};
    use alloy::{
        eips::BlockId,
        network::BlockResponse,
        providers::{Provider, ProviderBuilder},
        rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag,
    };
    use alloy_primitives::{address, Address};

    const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
    const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

    #[tokio::test]
    #[ignore] // This queries actual RPC nodes, running only on demand.
    async fn beacon_roots_contract() {
        let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();
        let latest = el
            .get_block_by_number(AlloyBlockNumberOrTag::Latest, false)
            .await
            .expect("eth_getBlockByNumber failed")
            .unwrap();
        let header = latest.header();
        let calldata = U256::from(header.timestamp);

        let (preflight, state) =
            BeaconRootsContract::preflight_get(calldata, el, header.hash.into())
                .await
                .unwrap();
        assert_eq!(state.root(), header.state_root);
        assert_eq!(
            preflight,
            dbg!(BeaconRootsContract::new(state).get(calldata))
        );
        assert_eq!(preflight, header.parent_beacon_block_root.unwrap());
    }

    #[tokio::test]
    #[ignore] // This queries actual RPC nodes, running only on demand.
    async fn history_input() {
        const USDT_ADDRESS: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
        alloy::sol! {
            interface IERC20 {
                function symbol() external view returns (string memory);
            }
        }

        let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        // use Finalized for the state header
        let mut env = EthEvmEnv::builder()
            .provider(el.clone())
            .block_number_or_tag(BlockNumberOrTag::Finalized)
            .beacon_api(CL_URL.parse().unwrap())
            .commitment_block(BlockNumberOrTag::Parent)
            .build()
            .await
            .unwrap();
        Contract::preflight(USDT_ADDRESS, &mut env)
            .call_builder(&IERC20::symbolCall {})
            .call()
            .await
            .unwrap();

        let input = env.into_input().await.unwrap();

        // check commitment against latest
        let commit = dbg!(input.into_env().into_commitment());
        let (beacon_root, _) = BeaconRootsContract::preflight_get(
            U256::from(commit.block_id()),
            &el,
            BlockId::latest(),
        )
        .await
        .unwrap();
        assert_eq!(beacon_root, commit.blockDigest);
    }
}
