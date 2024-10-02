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
    beacon, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput,
    EvmBlockHeader, MerkleTrie,
};
use alloy_primitives::{b256, keccak256, Sealed, B256, U256};
use beacon::{GeneralizedBeaconCommit, STATE_ROOT_LEAF_INDEX, BeaconCommit};
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
        // first, compute the beacon commit of the EVM execution
        let commitment = self.evm_commit.commit(header);
        let (timestamp, version) = Commitment::decode_id(commitment.blockID);
        assert_eq!(version, CommitmentVersion::Beacon as u16);

        // then verify that commitment wrt the given state
        let state_root = self.state.root();
        let commitment_root = BeaconRootsContract::get_from_state(self.state, timestamp)
            .expect("Beacon roots contract failed");
        assert_eq!(
            commitment_root, commitment.blockDigest,
            "Beacon root does not match"
        );

        // finally return the beacon commitment of the given state
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
    use alloy_primitives::{address, uint, Address};
    use anyhow::Context;

    /// Enum representing possible errors that can occur within the `BeaconRootsContract`.
    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        /// Error indicating that the contract is not deployed at the expected address.
        #[error("wrong or no contract deployed")]
        NoContract,
        /// Error indicating an inconsistency in the contract's state.
        #[error("inconsistent state")]
        InvalidState,
        /// Error indicating that the state contains improperly encoded data.
        #[error("state contains invalid encoded data")]
        InvalidEncoding(#[from] alloy_rlp::Error),
        /// Error indicating that the contract execution was reverted.
        #[error("execution reverted")]
        Reverted,
    }

    /// The `State` struct represents the state of the contract.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct State {
        pub state_trie: MerkleTrie,
        pub storage_trie: MerkleTrie,
    }

    impl State {
        /// Computes the state root.
        #[inline]
        pub fn root(&self) -> B256 {
            self.state_trie.hash_slow()
        }
    }

    /// The `BeaconRootsContract` is responsible for storing and retrieving historical beacon roots.
    ///
    /// It is an exact reimplementation of the beacon roots contract as defined in [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).
    /// It is deployed at the address `000F3df6D732807Ef1319fB7B8bB8522d0Beac02` and has the
    /// following storage layout:
    /// - `timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH`: Stores the timestamp at this index.
    /// - `root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH`: Stores the beacon root at this index.
    pub struct BeaconRootsContract {
        storage: MerkleTrie,
    }

    impl BeaconRootsContract {
        /// The length of the buffer that stores historical entries, i.e., the number of stored
        /// timestamps and roots.
        pub const HISTORY_BUFFER_LENGTH: U256 = uint!(8191_U256);
        /// Address where the contract is deployed.
        pub const ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

        /// Hash of the contract's address, where the contract is deployed.
        const ADDRESS_HASH: B256 =
            b256!("37d65eaa92c6bc4c13a5ec45527f0c18ea8932588728769ec7aecfe6d9f32e42");
        /// Hash of the deployed EVM bytecode.
        const CODE_HASH: B256 =
            b256!("f57acd40259872606d76197ef052f3d35588dadf919ee1f0e3cb9b62d3f4b02c");

        /// Creates a new instance of the `BeaconRootsContract` by verifying the provided state.
        pub fn new(state: State) -> Result<Self, Error> {
            // retrieve the account data from the state trie using the contract's address hash
            let account: StateAccount = state
                .state_trie
                .get_rlp(Self::ADDRESS_HASH)?
                .unwrap_or_default();
            // validate the account's code hash and storage root
            if account.code_hash != Self::CODE_HASH {
                return Err(Error::NoContract);
            }
            let storage = state.storage_trie;
            if storage.hash_slow() != account.storage_root {
                return Err(Error::InvalidState);
            }

            Ok(Self { storage })
        }

        /// Retrieves the root associated with the provided `calldata` (timestamp).
        ///
        /// This behaves exactly like the EVM bytecode defined in EIP-4788.
        pub fn get(&self, calldata: U256) -> Result<B256, Error> {
            if calldata.is_zero() {
                return Err(Error::Reverted);
            }

            let timestamp_idx = calldata % Self::HISTORY_BUFFER_LENGTH;
            let timestamp = self.storage_get(timestamp_idx)?;

            if timestamp != calldata {
                return Err(Error::Reverted);
            }

            let root_idx = timestamp_idx + Self::HISTORY_BUFFER_LENGTH;
            let root = self.storage_get(root_idx)?;

            Ok(root.into())
        }

        /// Retrieves the root from a given `State` based on the provided `calldata` (timestamp).
        #[inline]
        pub fn get_from_state(state: State, calldata: U256) -> Result<B256, Error> {
            Self::new(state)?.get(calldata)
        }

        /// Retrieves a value from the contract's storage at the given index.
        fn storage_get(&self, index: U256) -> Result<U256, Error> {
            Ok(self
                .storage
                .get_rlp(keccak256(index.to_be_bytes::<32>()))?
                .unwrap_or_default())
        }

        /// Prepares and retrieves the beacon root from an RPC provider by constructing the
        /// necessary proof.
        ///
        /// It fetches the minimal set of Merkle proofs (for the contract's state and storage)
        /// required to verify and retrieve the beacon root associated with the given `calldata`
        /// (timestamp). It leverages the Ethereum `eth_getProof` RPC to get the account and
        /// storage proofs needed to validate the contract's state and storage.
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
            // compute the keys of the two storage slots that will be accessed
            let timestamp_idx = calldata % Self::HISTORY_BUFFER_LENGTH;
            let root_idx = timestamp_idx + Self::HISTORY_BUFFER_LENGTH;

            // derive the minimal state needed to query and validate
            let proof = provider
                .get_proof(Self::ADDRESS, vec![timestamp_idx.into(), root_idx.into()])
                .block_id(block_id)
                .await
                .context("eth_getProof failed")?;
            let state = State {
                state_trie: MerkleTrie::from_rlp_nodes(proof.account_proof)?,
                storage_trie: MerkleTrie::from_rlp_nodes(
                    proof.storage_proof.iter().flat_map(|p| &p.proof),
                )?,
            };
            // validate the returned state and compute the return value
            let returns = Self::get_from_state(state.clone(), calldata)
                .context("API returned invalid state")?;

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

        // querying the contract for the latest timestamp should return parent_beacon_block_root
        let calldata = U256::from(header.timestamp);
        let (preflight, state) =
            BeaconRootsContract::preflight_get(calldata, el, header.hash.into())
                .await
                .unwrap();
        assert_eq!(state.root(), header.state_root);
        assert_eq!(preflight, header.parent_beacon_block_root.unwrap());
        // executing the contract from the exact state should return the same value
        assert_eq!(
            preflight,
            dbg!(BeaconRootsContract::get_from_state(state, calldata)).unwrap()
        );
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
