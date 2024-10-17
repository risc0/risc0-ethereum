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
    beacon, BlockHeaderCommit, Commitment, CommitmentVersion, ComposeInput, EvmBlockHeader,
};
use alloy_primitives::{Sealed, B256, U256};
use beacon::{BeaconCommit, GeneralizedBeaconCommit, STATE_ROOT_LEAF_INDEX};
use beacon_roots::BeaconRootsContract;
use serde::{Deserialize, Serialize};

mod beacon_roots;

/// Input committing a previous block hash to the corresponding Beacon Chain block root.
pub type HistoryInput<H> = ComposeInput<H, HistoryCommit>;

/// Verifiable proof that an execution block hash is included in the past of a specific beacon block
/// on the Ethereum blockchain.
///
/// This struct encapsulates the necessary data to prove that a given execution block is part of the
/// canonical chain according to the Beacon Chain.
#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryCommit {
    /// Commit of the Steel EVM execution block hash to its beacon block hash.
    evm_commit: BeaconCommit,
    /// State for verifying `evm_commit`.
    state: beacon_roots::State,
    /// Commitment for `state` to a beacon block hash.
    state_commit: GeneralizedBeaconCommit<STATE_ROOT_LEAF_INDEX>,
}

impl<H: EvmBlockHeader> BlockHeaderCommit<H> for HistoryCommit {
    /// Generates a commitment that proves the given block header is included in the Beacon Chain's
    /// history.
    #[inline]
    fn commit(self, header: &Sealed<H>, config_id: B256) -> Commitment {
        // first, compute the beacon commit of the EVM execution
        let commitment = self.evm_commit.commit(header, config_id);
        let (timestamp, version) = commitment.decode_id();
        assert_eq!(version, CommitmentVersion::Beacon as u16);

        // then verify that commitment wrt the given state
        let state_root = self.state.root();
        let commitment_root = BeaconRootsContract::get_from_state(self.state, timestamp)
            .expect("Beacon roots contract failed");
        assert_eq!(
            commitment_root, commitment.digest,
            "Beacon root does not match"
        );

        // finally return the beacon commitment of the given state
        let (timestamp, beacon_root) = self.state_commit.into_commit(state_root);
        Commitment::new(
            CommitmentVersion::Beacon as u16,
            timestamp,
            beacon_root,
            commitment.configID,
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
    use alloy::{network::Ethereum, providers::Provider, transports::Transport};
    use anyhow::Context;
    use url::Url;

    impl HistoryCommit {
        /// Creates a new `HistoryCommit` for the provided beacon commit and header which proofs
        /// that that commit was valid at a previous state of the blockchain represented by
        /// `header`.
        pub(crate) async fn from_beacon_commit_and_header<T, P>(
            history_commit: BeaconCommit,
            header: &Sealed<EthBlockHeader>,
            rpc_provider: P,
            beacon_url: Url,
        ) -> anyhow::Result<Self>
        where
            T: Transport + Clone,
            P: Provider<T, Ethereum>,
        {
            // derive the historic state needed to verify the EVM execution commitment
            let (_, state) = BeaconRootsContract::preflight_get(
                U256::from(history_commit.timestamp()),
                &rpc_provider,
                header.seal().into(),
            )
            .await
            .with_context(|| {
                format!(
                    "preflight of BeaconRootsContract failed for block {}",
                    header.seal()
                )
            })?;

            // create a beacon commitment to that historic state for the given header
            let client = BeaconClient::new(beacon_url).context("invalid URL")?;
            let (state_commit, beacon_root) =
                create_beacon_commit(header, "state_root".into(), &rpc_provider, &client).await?;
            state_commit
                .verify(state.root(), beacon_root)
                .context("proof derived from API does not verify")?;

            log::info!(
                "Committing to parent beacon block: root={},timestamp={}",
                beacon_root,
                state_commit.timestamp()
            );

            Ok(HistoryCommit {
                evm_commit: history_commit,
                state,
                state_commit,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum::EthBlockHeader;
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy_primitives::Sealable;

    const EL_URL: &str = "https://ethereum-rpc.publicnode.com";
    const CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

    #[tokio::test]
    #[ignore] // This queries actual RPC nodes, running only on demand.
    async fn from_beacon_commit_and_header() {
        let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        // get the latest 4 headers
        let headers = get_headers(4).await.unwrap();

        // create a beacon commitment to header[0]
        let beacon_commit = BeaconCommit::from_header(&headers[0], &el, CL_URL.parse().unwrap())
            .await
            .unwrap();
        // create a history commitment to header[2]
        let commit = HistoryCommit::from_beacon_commit_and_header(
            beacon_commit.clone(),
            &headers[2],
            &el,
            CL_URL.parse().unwrap(),
        )
        .await
        .unwrap();

        // the state commit should verify against the beacon block root of headers[2]
        commit
            .state_commit
            .verify(
                commit.state.root(),
                headers[3].parent_beacon_block_root.unwrap(),
            )
            .unwrap();
        // the beacon roots contract should return the beacon block root of headers[0]
        assert_eq!(
            BeaconRootsContract::get_from_state(
                commit.state.clone(),
                U256::from(commit.evm_commit.timestamp())
            )
            .unwrap(),
            headers[1].parent_beacon_block_root.unwrap(),
        );
        // the beacon commit of the EVM execution should be included
        assert_eq!(
            commit.evm_commit.clone().into_parts(),
            beacon_commit.into_parts()
        );
        // the resulting commitment should correspond to the beacon block root of headers[2]
        assert_eq!(
            commit.commit(&headers[0], B256::ZERO).digest,
            headers[3].parent_beacon_block_root.unwrap()
        );
    }

    async fn get_headers(n: usize) -> anyhow::Result<Vec<Sealed<EthBlockHeader>>> {
        let el = ProviderBuilder::new().on_builtin(EL_URL).await?;
        let latest = el.get_block_number().await?;

        let mut headers = Vec::with_capacity(n);
        for number in latest + 1 - (n as u64)..=latest {
            let block = el.get_block_by_number(number.into(), false).await?.unwrap();
            let header: EthBlockHeader = block.header.try_into()?;
            headers.push(header.seal_slow());
        }

        Ok(headers)
    }
}
