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

//! Types related to commitments to a historical state.
use crate::{
    beacon, beacon::BeaconBlockId, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput,
};
use alloy_primitives::{Sealed, B256, U256};
use beacon::{BeaconCommit, GeneralizedBeaconCommit, STATE_ROOT_LEAF_INDEX};
use beacon_roots::{BeaconRootsContract, BeaconRootsState};
use serde::{Deserialize, Serialize};

pub(crate) mod beacon_roots;

/// Input committing a previous block hash to the corresponding Beacon Chain block root.
pub type HistoryInput<F> = ComposeInput<F, HistoryCommit>;

/// A commitment that an execution block is included as an ancestor of a specific beacon block on
/// the Ethereum blockchain.
///
/// This struct encapsulates the necessary data to prove that a given execution block is part of the
/// canonical chain according to the Beacon Chain.
#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryCommit {
    /// Commit of the Steel EVM execution block hash to its beacon block hash.
    evm_commit: BeaconCommit,
    /// Iterative commits for verifying `evm_commit` as an ancestor of some valid Beacon block.
    state_commits: Vec<StateCommit>,
}

/// Represents a commitment of a beacon roots contract state to a Beacon Chain block root.
#[derive(Clone, Serialize, Deserialize)]
struct StateCommit {
    /// State for verifying `evm_commit`.
    state: BeaconRootsState,
    /// Commitment for `state` to a Beacon Chain block root.
    state_commit: GeneralizedBeaconCommit<STATE_ROOT_LEAF_INDEX>,
}

impl<H> BlockHeaderCommit<H> for HistoryCommit {
    /// Generates a commitment that proves the given block header is included in the Beacon Chain's
    /// history. Panics if the provided [HistoryCommit] data is invalid or inconsistent.
    #[inline]
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment {
        // first, compute the beacon commit of the EVM execution
        let evm_commitment = self.evm_commit.commit(header, config_id);
        let (id, version) = evm_commitment.decode_id();
        // just a sanity check, a BeaconCommit will always have this version
        assert_eq!(version, CommitmentVersion::Beacon as u16);

        let mut beacon_block_id = BeaconBlockId::Eip4788(id.to());
        let mut beacon_root = evm_commitment.digest;

        // starting from evm_commit, "walk forward" along state_commits to reach a later beacon root
        for mut state_commit in self.state_commits {
            // verify that the previous commitment is valid wrt the current state
            let state_root = state_commit.state.root();
            let timestamp = match beacon_block_id {
                BeaconBlockId::Eip4788(ts) => U256::from(ts),
                BeaconBlockId::Slot(_) => panic!("Invalid state commitment: wrong version"),
            };
            let commitment_root =
                BeaconRootsContract::get_from_db(&mut state_commit.state, timestamp)
                    .expect("Beacon roots contract failed");
            assert_eq!(commitment_root, beacon_root, "Beacon root does not match");

            // compute the beacon commitment of the current state
            (beacon_block_id, beacon_root) = state_commit.state_commit.into_commit(state_root);
        }

        Commitment::new(
            beacon_block_id.as_version(),
            beacon_block_id.as_id(),
            beacon_root,
            evm_commitment.configID,
        )
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::{
        beacon::{
            host::{client::BeaconClient, create_beacon_commit},
            BeaconBlockId,
        },
        ethereum::EthBlockHeader,
        history::beacon_roots::BeaconRootsState,
        EvmBlockHeader,
    };
    use alloy::{network::Ethereum, providers::Provider};
    use anyhow::{ensure, Context};
    use url::Url;

    impl HistoryCommit {
        /// Creates a `HistoryCommit` from an EVM execution block header and a later commitment
        /// header.
        ///
        /// This method constructs a chain of proofs to link the `execution_header` to the
        /// `commitment_header` via the Beacon Chain and the EIP-4788 beacon roots contract.
        /// It effectively proves that the `execution_header` is an ancestor of a state verifiable
        /// by the `commitment_header`.
        pub(crate) async fn from_headers<P>(
            execution_header: &Sealed<EthBlockHeader>,
            commitment_header: &Sealed<EthBlockHeader>,
            commitment_version: CommitmentVersion,
            rpc_provider: P,
            beacon_url: Url,
        ) -> anyhow::Result<Self>
        where
            P: Provider<Ethereum>,
        {
            ensure!(
                execution_header.number() < commitment_header.number(),
                "EVM execution block not before commitment block"
            );
            let client = BeaconClient::new(beacon_url.clone()).context("invalid URL")?;

            // 1. Create a beacon commitment for the execution_header.
            // This establishes the target beacon root we need to eventually verify.
            let evm_commit = BeaconCommit::from_header(
                execution_header,
                CommitmentVersion::Beacon,
                &rpc_provider,
                beacon_url,
            )
            .await
            .context("failed to create beacon commit for the execution header")?;
            let execution_commit = match evm_commit.clone().into_commit(execution_header.seal()) {
                (BeaconBlockId::Eip4788(ts), beacon_root) => (U256::from(ts), beacon_root),
                // CommitmentVersion::Beacon should always yield Eip4788
                _ => unreachable!(),
            };

            // 2. Initialize the backward chaining process starting from the commitment_header.
            // current_state_block_hash is the block hash whose state we are currently inspecting
            // current_state_commit is the beacon commit for current_state_block_hash's state
            let mut current_state_block_hash = commitment_header.seal();
            let (mut current_state_commit, _) = create_beacon_commit(
                commitment_header,
                "state_root".into(), // we need to prove the state_root of the commitment_header
                commitment_version,
                &rpc_provider,
                &client,
            )
            .await
            .context("failed to create beacon commit for the commitment header")?;

            let mut state_commits: Vec<StateCommit> = Vec::new();

            // loop backwards until we link to `execution_header`'s beacon root
            loop {
                log::debug!("Processing state for block: {}", current_state_block_hash);

                // 2a. Query the beacon roots contract *within the current state* for the timestamp
                // in the slot that the execution commit will eventually occupy,
                let timestamp = beacon_roots::get_timestamp(
                    execution_commit.0,
                    &rpc_provider,
                    current_state_block_hash.into(),
                )
                .await
                .context("failed to get timestamp from beacon roots contract")?;
                // 2b. Preflight the beacon roots contract call for timestamp. This gives us the
                // BeaconRootsState and the parent_beacon_root of that particular call.
                let (parent_beacon_root, state_proof) = BeaconRootsState::preflight_get(
                    timestamp,
                    &rpc_provider,
                    current_state_block_hash.into(),
                )
                .await
                .context("failed to preflight beacon roots contract")?;

                // 2c. Store the fetched BeaconRootsState and its beacon commitment
                // These are inserted at the beginning as we are building the chain in reverse.
                state_commits.insert(
                    0,
                    StateCommit {
                        state: state_proof,
                        state_commit: current_state_commit,
                    },
                );

                // 2d. Check if the chain is complete. This happens if the beacon roots contract
                // actually contained the execution commit.
                if timestamp == execution_commit.0 {
                    // if timestamps match, the parent beacon root must also match
                    ensure!(
                        parent_beacon_root == execution_commit.1,
                        "failed to verify final beacon commit"
                    );
                    break; // chain successfully linked
                }

                // 2e. If not yet linked, prepare for the next iteration. The parent_beacon_root is
                // the beacon root of an *earlier* block's state, and we need to find that
                // execution block and repeat the process with its state.
                current_state_block_hash = client
                    .get_execution_payload_block_hash(parent_beacon_root)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to get execution payload block hash for beacon block {}",
                            parent_beacon_root
                        )
                    })?;
                // create the beacon commitment for the next state
                current_state_commit = GeneralizedBeaconCommit::from_beacon_root(
                    "state_root".into(),
                    parent_beacon_root,
                    &client,
                    // in the current state, timestamp can be used to look up parent_beacon_root
                    BeaconBlockId::Eip4788(timestamp.to()),
                )
                .await
                .with_context(|| {
                    format!(
                        "Failed to create beacon commit for new state block hash {}",
                        current_state_block_hash
                    )
                })?;
            }

            log::debug!("Generated {} state commitments", state_commits.len());

            Ok(HistoryCommit {
                evm_commit,
                state_commits,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum::EthBlockHeader;
    use crate::test_utils::{get_cl_url, get_el_url};
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy_primitives::Sealable;

    #[tokio::test]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn from_beacon_commit_and_header() {
        let el = ProviderBuilder::default().connect_http(get_el_url());

        // get the latest 4 headers
        let headers = get_headers(4).await.unwrap();

        // create a history commitment executing on header[0] and committing to header[2]
        let mut commit = HistoryCommit::from_headers(
            &headers[0],
            &headers[2],
            CommitmentVersion::Beacon,
            &el,
            get_cl_url(),
        )
        .await
        .unwrap();

        let [StateCommit {
            state,
            state_commit,
        }] = &mut commit.state_commits[..]
        else {
            panic!("invalid state_commits")
        };

        // the state commit should verify against the beacon block root of headers[2]<
        state_commit
            .verify(state.root(), headers[3].parent_beacon_block_root.unwrap())
            .unwrap();
        // the beacon roots contract should return the beacon block root of headers[0]
        assert_eq!(
            BeaconRootsContract::get_from_db(
                state,
                U256::from(commit.evm_commit.block_id().as_id())
            )
            .unwrap(),
            headers[1].parent_beacon_block_root.unwrap(),
        );
        // the resulting commitment should correspond to the beacon block root of headers[2]
        assert_eq!(
            commit.commit(&headers[0], B256::ZERO).digest,
            headers[3].parent_beacon_block_root.unwrap()
        );
    }

    // get the latest n headers, with header[0] being the oldest and header[n-1] being the newest.
    async fn get_headers(n: usize) -> anyhow::Result<Vec<Sealed<EthBlockHeader>>> {
        let el = ProviderBuilder::new().connect_http(get_el_url());
        let latest = el.get_block_number().await?;

        let mut headers = Vec::with_capacity(n);
        for number in latest + 1 - (n as u64)..=latest {
            let block = el.get_block_by_number(number.into()).await?.unwrap();
            let header: EthBlockHeader = block.header.try_into()?;
            headers.push(header.seal_slow());
        }

        Ok(headers)
    }
}
