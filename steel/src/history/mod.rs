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

//! Types related to commitments to a historical state.
use crate::{
    beacon, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput, EvmBlockHeader,
};
use alloy_primitives::{Sealed, B256, U256};
use beacon::{BeaconCommit, GeneralizedBeaconCommit, STATE_ROOT_LEAF_INDEX};
use beacon_roots::BeaconRootsContract;
use serde::{Deserialize, Serialize};
mod beacon_roots;

/// Input committing a previous block hash to the corresponding Beacon Chain block root.
pub type HistoryInput<H> = ComposeInput<H, HistoryCommit>;

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
    state: beacon_roots::State,
    /// Commitment for `state` to a Beacon Chain block root.
    state_commit: GeneralizedBeaconCommit<STATE_ROOT_LEAF_INDEX>,
}

impl<H: EvmBlockHeader> BlockHeaderCommit<H> for HistoryCommit {
    /// Generates a commitment that proves the given block header is included in the Beacon Chain's
    /// history. Panics if the provided [HistoryCommit] data is invalid or inconsistent.
    #[inline]
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment {
        // first, compute the beacon commit of the EVM execution
        let initial_commitment = self.evm_commit.commit(header, config_id);
        let (mut timestamp, version) = initial_commitment.decode_id();
        // just a sanity check, a BeaconCommit will always have this version
        assert_eq!(version, CommitmentVersion::Beacon as u16);

        // starting from evm_commit, "walk forward" along state_commits to reach a later beacon root
        let mut beacon_root = initial_commitment.digest;
        for state_commit in self.state_commits {
            // verify that the previous commitment is valid wrt the current state
            let state_root = state_commit.state.root();
            let commitment_root =
                BeaconRootsContract::get_from_state(state_commit.state, timestamp)
                    .expect("Beacon roots contract failed");
            assert_eq!(commitment_root, beacon_root, "Beacon root does not match");

            // compute the beacon commitment of the current state
            let (commit_ts, commit_beacon_root) = state_commit.state_commit.into_commit(state_root);
            timestamp = U256::from(commit_ts);
            beacon_root = commit_beacon_root;
        }

        Commitment::new(
            CommitmentVersion::Beacon as u16,
            timestamp.to(),
            beacon_root,
            initial_commitment.configID,
        )
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::{
        beacon::host::{client::BeaconClient, create_beacon_commit},
        ethereum::EthBlockHeader,
    };
    use alloy::{
        network::{primitives::BlockTransactionsKind, Ethereum},
        providers::Provider,
        transports::Transport,
    };
    use alloy_primitives::{BlockNumber, Sealable};
    use anyhow::{ensure, Context};
    use url::Url;

    impl HistoryCommit {
        /// Creates a `HistoryCommit` from an EVM block header and a commitment header.
        ///
        /// This method fetches the necessary data from the Ethereum and Beacon chain to construct a
        /// `HistoryCommit`. It iterates through blocks from the EVM header's number up to
        /// the commitment header's number, generating `StateCommit`s for each block in the range.
        pub(crate) async fn from_headers<T, P>(
            evm_header: &Sealed<EthBlockHeader>,
            commitment_header: &Sealed<EthBlockHeader>,
            rpc_provider: P,
            beacon_url: Url,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            P: Provider<T, Ethereum>,
        {
            ensure!(
                evm_header.number() < commitment_header.number(),
                "EVM execution block not before commitment block"
            );
            let client = BeaconClient::new(beacon_url.clone()).context("invalid URL")?;

            // create a regular beacon commit to the block header used for EVM execution
            let evm_commit =
                BeaconCommit::from_header(evm_header, &rpc_provider, beacon_url).await?;
            let mut commit_ts = evm_commit.timestamp();
            // safe unwrap: BeaconCommit::from_header checks that the proof can be processed
            let mut commit_beacon_root = evm_commit.process_proof(evm_header.seal()).unwrap();

            let mut state_commits: Vec<StateCommit> = Vec::new();

            // we assume that not more than 25% of the blocks have been skipped
            // TODO(#309): implement a more sophisticated way to determine the step size
            let step = BeaconRootsContract::HISTORY_BUFFER_LENGTH.to::<BlockNumber>() * 75 / 100;
            let target = commitment_header.number();

            let mut state_block = evm_header.number;
            while state_block < target {
                state_block = std::cmp::min(state_block + step, target);

                // get the header of the state block
                let rpc_block = rpc_provider
                    .get_block_by_number(state_block.into(), BlockTransactionsKind::Hashes)
                    .await
                    .context("eth_getBlockByNumber failed")?
                    .with_context(|| format!("block {} not found", state_block))?;
                let header: EthBlockHeader = rpc_block
                    .header
                    .try_into()
                    .with_context(|| format!("block {} invalid", state_block))?;
                let header = header.seal_slow();

                log::debug!(
                    "chained commitment for block {} ({})",
                    header.number,
                    header.seal()
                );

                // derive the historic state needed to verify the previous beacon commitment
                let (beacon_root, state) = BeaconRootsContract::preflight_get(
                    U256::from(commit_ts),
                    &rpc_provider,
                    header.seal().into(),
                )
                .await
                .with_context(|| format!("preflight failed for block {}", header.seal()))?;
                // the result of the beacon roots contract must match the beacon root of the commit
                ensure!(
                    beacon_root == commit_beacon_root,
                    "inconsistent state for block {}",
                    header.seal()
                );

                // create a beacon commitment to that state
                let (state_commit, beacon_root) =
                    create_beacon_commit(&header, "state_root".into(), &rpc_provider, &client)
                        .await?;
                state_commit
                    .verify(state.root(), beacon_root)
                    .context("proof derived from API does not verify")?;
                commit_ts = state_commit.timestamp();
                commit_beacon_root = beacon_root;

                state_commits.push(StateCommit {
                    state,
                    state_commit,
                });
            }

            log::debug!("state commitments: {}", state_commits.len());

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
    use alloy::{
        network::primitives::BlockTransactionsKind,
        providers::{Provider, ProviderBuilder},
    };
    use alloy_primitives::Sealable;

    const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
    const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

    #[tokio::test]
    #[ignore = "queries actual RPC nodes"]
    async fn from_beacon_commit_and_header() {
        let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        // get the latest 4 headers
        let headers = get_headers(4).await.unwrap();

        // create a history commitment executing on header[0] and committing to header[2]
        let commit =
            HistoryCommit::from_headers(&headers[0], &headers[2], &el, CL_URL.parse().unwrap())
                .await
                .unwrap();

        let [StateCommit {
            state,
            state_commit,
        }] = &commit.state_commits[..]
        else {
            panic!("invalid state_commits")
        };

        // the state commit should verify against the beacon block root of headers[2]
        state_commit
            .verify(state.root(), headers[3].parent_beacon_block_root.unwrap())
            .unwrap();
        // the beacon roots contract should return the beacon block root of headers[0]
        assert_eq!(
            BeaconRootsContract::get_from_state(
                state.clone(),
                U256::from(commit.evm_commit.timestamp())
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
        let el = ProviderBuilder::new().on_builtin(EL_URL).await?;
        let latest = el.get_block_number().await?;

        let mut headers = Vec::with_capacity(n);
        for number in latest + 1 - (n as u64)..=latest {
            let block = el
                .get_block_by_number(number.into(), BlockTransactionsKind::Hashes)
                .await?
                .unwrap();
            let header: EthBlockHeader = block.header.try_into()?;
            headers.push(header.seal_slow());
        }

        Ok(headers)
    }
}
