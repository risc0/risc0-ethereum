use alloy::{
    eips::BlockId,
    providers::{Provider, ProviderBuilder},
    transports::{Transport, TransportError},
};
use alloy_primitives::{address, Address, BlockNumber};
use op_alloy_network::Optimism;
use risc0_steel::{beacon::BeaconCommit, ethereum::EthEvmInput, BeaconInput};
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

/// Returns the latest L1 block number known in the OP network.
pub async fn latest_block_number<T, P>(provider: P) -> Result<BlockNumber, Error>
where
    T: Transport + Clone,
    P: Provider<T, Optimism>,
{
    Ok(L1Block::new(L1_BLOCK_ADDRESS, provider)
        .latest_number()
        .await?)
}

/// Derives the OP verifiable input from an L1 beacon input and an OP HTTP RPC url.
pub async fn into_beacon_input(input: EthEvmInput, url: Url) -> Result<EthEvmInput, Error> {
    into_beacon_input_with_provider(input, ProviderBuilder::default().on_http(url)).await
}

/// Derives the OP verifiable input from an L1 beacon input and an OP RPC provider.
pub async fn into_beacon_input_with_provider<T, P>(
    input: EthEvmInput,
    provider: P,
) -> Result<EthEvmInput, Error>
where
    T: Transport + Clone,
    P: Provider<T, Optimism>,
{
    let EthEvmInput::Beacon(input) = input else {
        panic!();
    };
    let (input, commit) = input.into_parts();
    let (proof, timestamp) = commit.into_parts();

    let block_contract = L1Block::new(L1_BLOCK_ADDRESS, &provider);
    if timestamp > block_contract.latest_timestamp().await? {
        return Err(Error::NotYetPropagated);
    }

    let block_number = block_contract
        .find_l2_block_at_timestamp(timestamp)
        .await?
        .ok_or(Error::NoBlockForTimestamp(timestamp))?;

    let block_response = provider
        .get_block_by_number(block_number.into(), false)
        .await?;
    let timestamp = block_response.unwrap().header.timestamp;

    Ok(EthEvmInput::Beacon(BeaconInput::new(
        input,
        BeaconCommit::new(proof, timestamp),
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

struct L1Block<T, P>(sol::IL1Block::IL1BlockInstance<T, P, Optimism>);

impl<T, P> L1Block<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Optimism>,
{
    pub const fn new(address: Address, provider: P) -> Self {
        Self(sol::IL1Block::new(address, provider))
    }

    pub async fn latest_number(&self) -> alloy::contract::Result<BlockNumber> {
        Ok(self.0.number().call().await?._0)
    }

    pub async fn latest_timestamp(&self) -> alloy::contract::Result<u64> {
        Ok(self.0.timestamp().call().await?._0)
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
            let ts = self.0.timestamp().call().block(mid.into()).await?._0;
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
        Ok((ts?._0, sq?._0))
    }
}
