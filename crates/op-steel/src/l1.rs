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

use alloy::{
    eips::BlockId,
    providers::{Provider, ProviderBuilder},
    transports::TransportError,
};
use alloy_primitives::{address, Address, BlockNumber};
use op_alloy_network::Optimism;
use risc0_steel::{
    beacon::{BeaconBlockId, BeaconCommit},
    ethereum::EthEvmInput,
    BeaconInput,
};
use std::{cmp::Ordering, future::IntoFuture};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("L1 block not yet propagated")]
    NotYetPropagated,
    #[error("no block found for L1 timestamp {0}")]
    NoBlockForTimestamp(u64),
    #[error(transparent)]
    Contract(#[from] alloy::contract::Error),
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Returns the latest L1 block number known on the OP network.
pub async fn latest_block_number<P>(provider: P) -> Result<BlockNumber, Error>
where
    P: Provider<Optimism>,
{
    Ok(L1Block::new(L1_BLOCK_ADDRESS, provider)
        .latest_number()
        .await?)
}

/// Derives the OP verifiable input from an L1 beacon input and an OP HTTP RPC url.
pub async fn into_beacon_input(input: EthEvmInput, url: Url) -> Result<EthEvmInput, Error> {
    into_beacon_input_with_provider(input, ProviderBuilder::default().connect_http(url)).await
}

/// Derives the OP verifiable input from an L1 beacon input and an OP RPC provider.
///
/// It panics when `input` is not [EthEvmInput::Beacon].
pub async fn into_beacon_input_with_provider<P>(
    input: EthEvmInput,
    provider: P,
) -> Result<EthEvmInput, Error>
where
    P: Provider<Optimism>,
{
    let EthEvmInput::Beacon(input) = input else {
        panic!("only EthEvmInput::Beacon is supported");
    };
    let (input, commit) = input.into_parts();
    let (proof, beacon_block_id) = commit.into_parts();
    let BeaconBlockId::Eip4788(timestamp) = beacon_block_id else {
        panic!("only BeaconBlockId::Eip4788 is supported");
    };

    let block_contract = L1Block::new(L1_BLOCK_ADDRESS, &provider);
    if timestamp > block_contract.latest_timestamp().await? {
        return Err(Error::NotYetPropagated);
    }

    let block_number = block_contract
        .find_l2_block_at_timestamp(timestamp)
        .await?
        .ok_or(Error::NoBlockForTimestamp(timestamp))?;

    let block_response = provider
        .get_block_by_number(block_number.into())
        .hashes()
        .await?;
    let timestamp = block_response.unwrap().header.timestamp;

    log::debug!("OP timestamp of beacon commit: {}", timestamp);

    Ok(EthEvmInput::Beacon(BeaconInput::new(
        input,
        BeaconCommit::new(proof, BeaconBlockId::Eip4788(timestamp)),
    )))
}

/// Address of the L1Block contract.
const L1_BLOCK_ADDRESS: Address = address!("4200000000000000000000000000000000000015");

mod sol {
    alloy::sol! {
        #[sol(rpc)]
        interface IL1Block {
            function hash() external view returns (bytes32);
            function number() external view returns (uint64);
            function sequenceNumber() external view returns (uint64);
            function timestamp() external view returns (uint64);
        }
    }
}

struct L1Block<P>(sol::IL1Block::IL1BlockInstance<P, Optimism>);

impl<P> L1Block<P>
where
    P: Provider<Optimism>,
{
    pub const fn new(address: Address, provider: P) -> Self {
        Self(sol::IL1Block::new(address, provider))
    }

    pub async fn latest_number(&self) -> alloy::contract::Result<BlockNumber> {
        self.0.number().call().await
    }

    pub async fn latest_timestamp(&self) -> alloy::contract::Result<u64> {
        self.0.timestamp().call().await
    }

    pub async fn find_l2_block_at_timestamp(
        &self,
        target_ts: u64,
    ) -> alloy::contract::Result<Option<u64>> {
        let latest = self.0.provider().get_block_number().await?;

        let mut hi = latest + 1;

        // initial probing to narrow down the search range
        let mut block = latest;
        let mut lo = loop {
            let (ts1, sq1) = self.fetch_block_data(block.into()).await?;
            match ts1.cmp(&target_ts) {
                Ordering::Less => break block + 1,
                Ordering::Equal => return Ok(Some(block)),
                Ordering::Greater => hi = block,
            }

            let block2 = block - (sq1 + 1);
            let (ts2, sq2) = self.fetch_block_data(block2.into()).await?;
            match ts2.cmp(&target_ts) {
                Ordering::Less => break block2 + 1,
                Ordering::Equal => return Ok(Some(block2)),
                Ordering::Greater => hi = block2,
            }

            // estimate next block to check based on timestamp differences per epoch
            block = block2 - (ts2 - target_ts) * (sq2 + 1) / (ts1 - ts2);
        };

        // binary search within the narrowed range
        while lo < hi {
            let mid = (lo + hi) / 2;
            let ts = self.0.timestamp().call().block(mid.into()).await?;
            match ts.cmp(&target_ts) {
                Ordering::Less => lo = mid + 1,
                Ordering::Equal => return Ok(Some(mid)),
                Ordering::Greater => hi = mid,
            }
        }

        Ok(None)
    }

    async fn fetch_block_data(&self, block: BlockId) -> alloy::contract::Result<(u64, u64)> {
        let timestamp = self.0.timestamp();
        let sequence_number = self.0.sequenceNumber();
        let (ts, sq) = tokio::join!(
            timestamp.call().block(block).into_future(),
            sequence_number.call().block(block).into_future()
        );
        Ok((ts?, sq?))
    }
}
