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

use crate::game::DisputeGameInput;
use op_alloy_network::{Network, Optimism};
use revm::{
    precompile::B256,
    primitives::{
        alloy_primitives::{BlockNumber, Sealable},
        BlockEnv, SpecId, U256,
    },
};
use risc0_steel::{
    config::{ChainSpec, ForkCondition},
    serde::RlpHeader,
    BlockInput, Commitment, EvmBlockHeader, EvmEnv, StateDb,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::LazyLock};

#[cfg(feature = "host")]
mod host;

#[cfg(feature = "host")]
pub use host::*;

/// The OP Mainnet [ChainSpec].
pub static OP_MAINNET_CHAIN_SPEC: LazyLock<ChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 10,
    forks: BTreeMap::from([
        (SpecId::BEDROCK, ForkCondition::Timestamp(1679079600)),
        (SpecId::REGOLITH, ForkCondition::Timestamp(1679079600)),
        (SpecId::CANYON, ForkCondition::Timestamp(1704992401)),
        (SpecId::ECOTONE, ForkCondition::Timestamp(1710374401)),
        (SpecId::FJORD, ForkCondition::Timestamp(1720627201)),
        (SpecId::GRANITE, ForkCondition::Timestamp(1726070401)),
    ]),
});

/// The OP Sepolia [ChainSpec].
pub static OP_SEPOLIA_CHAIN_SPEC: LazyLock<ChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 11155420,
    forks: BTreeMap::from([
        (SpecId::BEDROCK, ForkCondition::Block(0)),
        (SpecId::REGOLITH, ForkCondition::Timestamp(0)),
        (SpecId::CANYON, ForkCondition::Timestamp(1699981200)),
        (SpecId::ECOTONE, ForkCondition::Timestamp(1708534800)),
        (SpecId::FJORD, ForkCondition::Timestamp(1716998400)),
        (SpecId::GRANITE, ForkCondition::Timestamp(1723478400)),
    ]),
});

type OpHeader = <Optimism as Network>::Header;

/// [EvmBlockHeader] for Optimism.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpBlockHeader(pub RlpHeader<OpHeader>);

impl AsRef<OpHeader> for OpBlockHeader {
    #[inline]
    fn as_ref(&self) -> &OpHeader {
        self.0.inner()
    }
}

impl Sealable for OpBlockHeader {
    #[inline]
    fn hash_slow(&self) -> B256 {
        self.0.hash_slow()
    }
}

impl EvmBlockHeader for OpBlockHeader {
    #[inline]
    fn parent_hash(&self) -> &B256 {
        &self.0.inner().parent_hash
    }
    #[inline]
    fn number(&self) -> BlockNumber {
        self.0.inner().number
    }
    #[inline]
    fn timestamp(&self) -> u64 {
        self.0.inner().timestamp
    }
    #[inline]
    fn state_root(&self) -> &B256 {
        &self.0.inner().state_root
    }
    #[cfg(feature = "unstable-event")]
    #[inline]
    fn receipts_root(&self) -> &B256 {
        &self.0.inner().receipts_root
    }
    #[cfg(feature = "unstable-event")]
    #[inline]
    fn logs_bloom(&self) -> &alloy_primitives::Bloom {
        &self.0.inner().logs_bloom
    }

    #[inline]
    fn fill_block_env(&self, blk_env: &mut BlockEnv) {
        let header = self.0.inner();

        blk_env.number = U256::from(header.number);
        blk_env.coinbase = header.beneficiary;
        blk_env.timestamp = U256::from(header.timestamp);
        blk_env.gas_limit = U256::from(header.gas_limit);
        blk_env.basefee = U256::from(header.base_fee_per_gas.unwrap_or_default());
        blk_env.difficulty = header.difficulty;
        // technically, this is only valid after EIP-4399 but revm makes sure it is not used before
        blk_env.prevrandao = Some(header.mix_hash);
        if let Some(excess_blob_gas) = header.excess_blob_gas {
            blk_env.set_blob_excess_gas_and_price(excess_blob_gas, false)
        };
    }
}

#[cfg(feature = "host")]
impl<H> TryFrom<alloy::rpc::types::Header<H>> for OpBlockHeader
where
    OpHeader: TryFrom<H>,
{
    type Error = <OpHeader as TryFrom<H>>::Error;

    #[inline]
    fn try_from(value: alloy::rpc::types::Header<H>) -> Result<Self, Self::Error> {
        Ok(Self(RlpHeader::new(value.inner.try_into()?)))
    }
}

/// The serializable input to derive and validate an [EvmEnv] from.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
pub enum OpEvmInput {
    Block(BlockInput<OpBlockHeader>),
    DisputeGame(DisputeGameInput),
}

impl OpEvmInput {
    #[inline]
    pub fn into_env(self) -> EvmEnv<StateDb, OpBlockHeader, Commitment> {
        match self {
            OpEvmInput::Block(input) => input.into_env(),
            OpEvmInput::DisputeGame(input) => input.into_env(),
        }
    }
}
