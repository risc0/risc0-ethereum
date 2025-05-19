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

use crate::{
    history::beacon_roots::BeaconRootsContract, state::WrapStateDb, Commitment, EvmBlockHeader,
    EvmFactory, GuestEvmEnv,
};
use alloy_primitives::{B256, U256};
use anyhow::{ensure, Context};

/// Represents a verifier for validating Steel commitments within Steel.
///
/// The verifier is used to validate Steel commitments representing a historical blockchain state.
///
/// ### Usage
/// - **Preflight verification on the Host:** To prepare verification on the host environment and
///   build the necessary proof, use [SteelVerifier::preflight]. The environment can be initialized
///   using the [EthEvmEnv::builder] or [EvmEnv::builder].
/// - **Verification in the Guest:** To initialize the verifier in the guest environment, use
///   [SteelVerifier::new]. The environment should be constructed using [EvmInput::into_env].
///
/// ### Examples
/// ```rust,no_run
/// # use risc0_steel::{ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}, SteelVerifier, Commitment};
/// # use url::Url;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// // Host:
/// let rpc_url = Url::parse("https://ethereum-rpc.publicnode.com")?;
/// let mut env = EthEvmEnv::builder().rpc(rpc_url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
///
/// // Preflight the verification of a commitment
/// let commitment = Commitment::default(); // Your commitment here
/// SteelVerifier::preflight(&mut env).verify(&commitment).await?;
///
/// let evm_input = env.into_input().await?;
///
/// // Guest:
/// let evm_env = evm_input.into_env(&ETH_MAINNET_CHAIN_SPEC);
/// let verifier = SteelVerifier::new(&evm_env);
/// verifier.verify(&commitment); // Panics if verification fails
/// # Ok(())
/// # }
/// ```
///
/// [EthEvmEnv::builder]: crate::ethereum::EthEvmEnv
/// [EvmEnv::builder]: crate::EvmEnv
/// [EvmInput::into_env]: crate::EvmInput::into_env
pub struct SteelVerifier<E> {
    env: E,
}

impl<'a, F: EvmFactory> SteelVerifier<&'a GuestEvmEnv<F>> {
    /// Constructor for verifying Steel commitments in the guest.
    pub fn new(env: &'a GuestEvmEnv<F>) -> Self {
        Self { env }
    }

    /// Verifies the commitment in the guest and panics on failure.
    ///
    /// This includes checking that the `commitment.configID` matches the
    /// configuration ID associated with the current guest environment (`self.env.commit.configID`).
    #[inline]
    pub fn verify(&self, commitment: &Commitment) {
        self.verify_with_config_id(commitment, self.env.commit.configID);
    }

    /// Verifies the commitment in the guest against an explicitly provided configuration ID,
    /// and panics on failure.
    pub fn verify_with_config_id(&self, commitment: &Commitment, config_id: B256) {
        assert_eq!(commitment.configID, config_id, "Invalid config ID");
        let (id, version) = commitment.decode_id();
        match version {
            0 => {
                let block_number =
                    validate_block_number(self.env.header().inner(), id).expect("Invalid ID");
                let block_hash = self.env.db().block_hash(block_number);
                assert_eq!(block_hash, commitment.digest, "Invalid digest");
            }
            1 => {
                let db = WrapStateDb::new(self.env.db(), self.env.header());
                let beacon_root = BeaconRootsContract::get_from_db(db, id)
                    .expect("calling BeaconRootsContract failed");
                assert_eq!(beacon_root, commitment.digest, "Invalid digest");
            }
            v => unimplemented!("Invalid commitment version {}", v),
        }
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::{history::beacon_roots, host::HostEvmEnv};
    use anyhow::Context;
    use revm::Database;

    impl<'a, D, F: EvmFactory, C> SteelVerifier<&'a mut HostEvmEnv<D, F, C>>
    where
        D: crate::EvmDatabase + Send + 'static,
        beacon_roots::Error: From<<D as Database>::Error>,
        anyhow::Error: From<<D as Database>::Error>,
        <D as Database>::Error: Send + 'static,
    {
        /// Constructor for preflighting Steel commitment verifications on the host.
        ///
        /// Initializes the environment for verifying Steel commitments, fetching necessary data via
        /// RPC, and generating a storage proof for any accessed elements using
        /// [EvmEnv::into_input].
        ///
        /// [EvmEnv::into_input]: crate::EvmEnv::into_input
        pub fn preflight(env: &'a mut HostEvmEnv<D, F, C>) -> Self {
            Self { env }
        }

        /// Preflights the commitment verification on the host.
        ///
        /// This includes checking that the `commitment.configID` matches the
        /// configuration ID associated with the current host environment.
        #[inline]
        pub async fn verify(self, commitment: &Commitment) -> anyhow::Result<()> {
            let config_id = self.env.commit.config_id();
            self.verify_with_config_id(commitment, config_id).await
        }

        /// Preflights the commitment verification on the host against an explicitly provided
        /// configuration ID.
        pub async fn verify_with_config_id(
            self,
            commitment: &Commitment,
            config_id: B256,
        ) -> anyhow::Result<()> {
            log::info!("Executing preflight verifying {:?}", commitment);

            ensure!(commitment.configID == config_id, "invalid config ID");
            let (id, version) = commitment.decode_id();
            match version {
                0 => {
                    let block_number = validate_block_number(self.env.header().inner(), id)
                        .context("invalid ID")?;
                    let block_hash = self
                        .env
                        .spawn_with_db(move |db| db.block_hash(block_number))
                        .await?;
                    ensure!(block_hash == commitment.digest, "invalid digest");

                    Ok(())
                }
                1 => {
                    let beacon_root = self
                        .env
                        .spawn_with_db(move |db| BeaconRootsContract::get_from_db(db, id))
                        .await
                        .with_context(|| format!("calling BeaconRootsContract({}) failed", id))?;
                    ensure!(beacon_root == commitment.digest, "invalid digest");

                    Ok(())
                }
                v => unimplemented!("Invalid commitment version {}", v),
            }
        }
    }
}

fn validate_block_number(header: &impl EvmBlockHeader, block_number: U256) -> anyhow::Result<u64> {
    let block_number = block_number.try_into().context("invalid block number")?;
    // if block_number > header.number(), this will also be caught in the following `ensure`
    let diff = header.number().saturating_sub(block_number);
    ensure!(
        diff > 0 && diff <= 256,
        "valid range is the last 256 blocks (not including the current one)"
    );
    Ok(block_number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_el_url;
    use crate::{
        ethereum::{EthEvmEnv, ETH_MAINNET_CHAIN_SPEC},
        CommitmentVersion,
    };
    use alloy::{
        consensus::BlockHeader,
        network::{primitives::HeaderResponse, BlockResponse},
        providers::{Provider, ProviderBuilder},
        rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag,
    };
    use test_log::test;

    #[test(tokio::test)]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn verify_block_commitment() {
        let el = ProviderBuilder::new().connect_http(get_el_url());

        // create block commitment to the previous block
        let latest = el.get_block_number().await.unwrap();
        let block = el
            .get_block_by_number((latest - 1).into())
            .await
            .expect("eth_getBlockByNumber failed")
            .unwrap();
        let header = block.header();
        let commit = Commitment::new(
            CommitmentVersion::Block as u16,
            header.number(),
            header.hash(),
            ETH_MAINNET_CHAIN_SPEC.digest(),
        );

        // preflight the verifier
        let mut env = EthEvmEnv::builder()
            .provider(el)
            .chain_spec(&ETH_MAINNET_CHAIN_SPEC)
            .build()
            .await
            .unwrap();
        SteelVerifier::preflight(&mut env)
            .verify(&commit)
            .await
            .unwrap();

        // mock guest execution, by executing the verifier on the GuestEvmEnv
        let env = env
            .into_input()
            .await
            .unwrap()
            .into_env(&ETH_MAINNET_CHAIN_SPEC);
        SteelVerifier::new(&env).verify(&commit);
    }

    #[test(tokio::test)]
    #[cfg_attr(not(feature = "rpc-tests"), ignore = "RPC tests are disabled")]
    async fn verify_beacon_commitment() {
        let el = ProviderBuilder::new().connect_http(get_el_url());

        // create Beacon commitment from latest block
        let block = el
            .get_block_by_number(AlloyBlockNumberOrTag::Latest)
            .await
            .expect("eth_getBlockByNumber failed")
            .unwrap();
        let header = block.header();
        let commit = Commitment::new(
            CommitmentVersion::Beacon as u16,
            header.timestamp,
            header.parent_beacon_block_root.unwrap(),
            ETH_MAINNET_CHAIN_SPEC.digest(),
        );

        // preflight the verifier
        let mut env = EthEvmEnv::builder()
            .provider(el)
            .chain_spec(&ETH_MAINNET_CHAIN_SPEC)
            .build()
            .await
            .unwrap();
        SteelVerifier::preflight(&mut env)
            .verify(&commit)
            .await
            .unwrap();

        // mock guest execution, by executing the verifier on the GuestEvmEnv
        let env = env
            .into_input()
            .await
            .unwrap()
            .into_env(&ETH_MAINNET_CHAIN_SPEC);
        SteelVerifier::new(&env).verify(&commit);
    }
}
