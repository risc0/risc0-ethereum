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

use crate::history::beacon_roots::BeaconRootsContract;
use crate::state::WrapStateDb;
use crate::{Commitment, EvmBlockHeader, GuestEvmEnv};
use alloy_primitives::U256;
use anyhow::ensure;

pub struct Verifier<E> {
    env: E,
}

impl<'a, H: EvmBlockHeader> Verifier<&'a GuestEvmEnv<H>> {
    pub fn new(env: &'a GuestEvmEnv<H>) -> Self {
        Self { env }
    }

    pub fn verify(&self, commitment: &Commitment) {
        let (id, version) = commitment.decode_id();
        match version {
            0 => {
                let block_number =
                    validate_block_number(self.env.header().inner(), id).expect("Invalid id");
                let block_hash = self.env.db().block_hash(block_number);
                assert_eq!(block_hash, commitment.digest, "Invalid digest");
            }
            1 => {
                let db = WrapStateDb::new(self.env.db());
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
    use crate::history::beacon_roots;
    use crate::host::HostEvmEnv;
    use anyhow::Context;
    use revm::Database;

    impl<'a, D, H: EvmBlockHeader, C> Verifier<&'a mut HostEvmEnv<D, H, C>>
    where
        D: Database + Send + 'static,
        beacon_roots::Error: From<<D as Database>::Error>,
        anyhow::Error: From<<D as Database>::Error>,
        <D as Database>::Error: Send + 'static,
    {
        pub fn preflight(env: &'a mut HostEvmEnv<D, H, C>) -> Self {
            Self { env }
        }

        pub async fn verify(self, commitment: &Commitment) -> anyhow::Result<()> {
            log::info!("Executing preflight verifying {:?}", commitment);

            let (id, version) = commitment.decode_id();
            match version {
                0 => {
                    let block_number = validate_block_number(self.env.header().inner(), id)
                        .context("invalid id")?;
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
    let block_number: u64 = block_number.saturating_to();
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
    use crate::config::ChainSpec;
    use crate::ethereum::EthEvmEnv;
    use crate::CommitmentVersion;
    use alloy::consensus::BlockHeader;
    use alloy::network::primitives::BlockTransactionsKind;
    use alloy::network::primitives::HeaderResponse;
    use alloy::network::BlockResponse;
    use alloy::providers::Provider;
    use alloy::providers::ProviderBuilder;
    use alloy::rpc::types::BlockNumberOrTag as AlloyBlockNumberOrTag;
    use test_log::test;

    const EL_URL: &str = "https://ethereum-rpc.publicnode.com";

    #[test(tokio::test)]
    #[ignore = "queries actual RPC nodes"]
    async fn verify_block_commitment() {
        let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        // create block commitment to the previous block
        let latest = el.get_block_number().await.unwrap();
        let block = el
            .get_block_by_number((latest - 1).into(), BlockTransactionsKind::Hashes)
            .await
            .expect("eth_getBlockByNumber failed")
            .unwrap();
        let header = block.header();
        let commit = Commitment::new(
            CommitmentVersion::Block as u16,
            header.number(),
            header.hash(),
            ChainSpec::DEFAULT_DIGEST,
        );

        // preflight the verifier
        let mut env = EthEvmEnv::builder().provider(el).build().await.unwrap();
        Verifier::preflight(&mut env).verify(&commit).await.unwrap();

        // mock guest execution, by executing the verifier on the GuestEvmEnv
        let env = env.into_input().await.unwrap().into_env();
        Verifier::new(&env).verify(&commit);
    }

    #[test(tokio::test)]
    #[ignore = "queries actual RPC nodes"]
    async fn verify_beacon_commitment() {
        let el = ProviderBuilder::new().on_builtin(EL_URL).await.unwrap();

        // create Beacon commitment from latest block
        let block = el
            .get_block_by_number(AlloyBlockNumberOrTag::Latest, BlockTransactionsKind::Hashes)
            .await
            .expect("eth_getBlockByNumber failed")
            .unwrap();
        let header = block.header();
        let commit = Commitment::new(
            CommitmentVersion::Beacon as u16,
            header.timestamp,
            header.parent_beacon_block_root.unwrap(),
            ChainSpec::DEFAULT_DIGEST,
        );

        // preflight the verifier
        let mut env = EthEvmEnv::builder().provider(el).build().await.unwrap();
        Verifier::preflight(&mut env).verify(&commit).await.unwrap();

        // mock guest execution, by executing the verifier on the GuestEvmEnv
        let env = env.into_input().await.unwrap().into_env();
        Verifier::new(&env).verify(&commit);
    }
}
