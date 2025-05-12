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
use alloy_evm::{Database, EvmFactory as AlloyEvmFactory};
use alloy_op_evm::OpEvmFactory as AlloyOpEvmFactory;
use alloy_primitives::{Address, BlockNumber, Bytes, ChainId, Sealable, TxKind, B256};
use op_alloy_network::{Network, Optimism};
use op_revm::{spec::OpSpecId, OpTransaction};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    inspector::NoOpInspector,
};
use risc0_steel::{
    config::{ChainSpec, ForkCondition},
    serde::RlpHeader,
    BlockInput, Commitment, EvmBlockHeader, EvmEnv, EvmFactory, StateDb,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::Into, error::Error, sync::LazyLock};

#[cfg(feature = "host")]
mod host;

#[cfg(feature = "host")]
pub use host::*;

/// The OP Mainnet [ChainSpec].
pub static OP_MAINNET_CHAIN_SPEC: LazyLock<OpChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 10,
    forks: BTreeMap::from([
        (OpSpecId::BEDROCK, ForkCondition::Block(105235063)),
        (OpSpecId::REGOLITH, ForkCondition::Timestamp(0)),
        (OpSpecId::CANYON, ForkCondition::Timestamp(1704992401)),
        (OpSpecId::ECOTONE, ForkCondition::Timestamp(1710374401)),
        (OpSpecId::FJORD, ForkCondition::Timestamp(1720627201)),
        (OpSpecId::GRANITE, ForkCondition::Timestamp(1726070401)),
        (OpSpecId::HOLOCENE, ForkCondition::Timestamp(1736445601)),
        (OpSpecId::ISTHMUS, ForkCondition::Timestamp(1746806401)),
    ]),
});

/// The OP Sepolia [ChainSpec].
pub static OP_SEPOLIA_CHAIN_SPEC: LazyLock<OpChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 11155420,
    forks: BTreeMap::from([
        (OpSpecId::BEDROCK, ForkCondition::Block(0)),
        (OpSpecId::REGOLITH, ForkCondition::Timestamp(0)),
        (OpSpecId::CANYON, ForkCondition::Timestamp(1699981200)),
        (OpSpecId::ECOTONE, ForkCondition::Timestamp(1708534800)),
        (OpSpecId::FJORD, ForkCondition::Timestamp(1716998400)),
        (OpSpecId::GRANITE, ForkCondition::Timestamp(1723478400)),
        (OpSpecId::HOLOCENE, ForkCondition::Timestamp(1732633200)),
        (OpSpecId::ISTHMUS, ForkCondition::Timestamp(1744905600)),
    ]),
});

/// [EvmFactory] for Optimism.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OpEvmFactory;

impl EvmFactory for OpEvmFactory {
    type Evm<DB: Database> = <AlloyOpEvmFactory as AlloyEvmFactory>::Evm<DB, NoOpInspector>;
    type Tx = <AlloyOpEvmFactory as AlloyEvmFactory>::Tx;
    type Error<DBError: Error + Send + Sync + 'static> =
        <AlloyOpEvmFactory as AlloyEvmFactory>::Error<DBError>;
    type HaltReason = <AlloyOpEvmFactory as AlloyEvmFactory>::HaltReason;
    type Spec = <AlloyOpEvmFactory as AlloyEvmFactory>::Spec;
    type Header = OpBlockHeader;

    fn new_tx(address: Address, data: Bytes) -> Self::Tx {
        OpTransaction {
            base: TxEnv {
                caller: address,
                kind: TxKind::Call(address),
                data,
                chain_id: None,
                ..Default::default()
            },
            enveloped_tx: Some(Bytes::new()),
            ..Default::default()
        }
    }

    fn create_evm<DB: Database>(
        db: DB,
        chain_id: ChainId,
        spec: Self::Spec,
        header: &Self::Header,
    ) -> Self::Evm<DB> {
        let mut cfg_env = CfgEnv::new_with_spec(spec).with_chain_id(chain_id);
        cfg_env.disable_nonce_check = true;
        cfg_env.disable_balance_check = true;
        cfg_env.disable_block_gas_limit = true;
        // Disabled because eth_call is sometimes used with eoa senders
        cfg_env.disable_eip3607 = true;
        // The basefee should be ignored for eth_call
        cfg_env.disable_base_fee = true;

        let block_env = header.to_block_env(spec);

        AlloyOpEvmFactory::default().create_evm(db, (cfg_env, block_env).into())
    }
}

/// [ChainSpec] for Optimism.
pub type OpChainSpec = ChainSpec<OpSpecId>;

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
    type Spec = OpSpecId;

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
    #[inline]
    fn receipts_root(&self) -> &B256 {
        &self.0.inner().receipts_root
    }
    #[inline]
    fn logs_bloom(&self) -> &alloy_primitives::Bloom {
        &self.0.inner().logs_bloom
    }

    #[inline]
    fn to_block_env(&self, spec: OpSpecId) -> BlockEnv {
        let header = self.0.inner();

        BlockEnv {
            number: header.number,
            beneficiary: header.beneficiary,
            timestamp: header.timestamp,
            gas_limit: header.gas_limit,
            basefee: header.base_fee_per_gas.unwrap_or_default(),
            difficulty: header.difficulty,
            prevrandao: (spec >= OpSpecId::BEDROCK).then_some(header.mix_hash),
            blob_excess_gas_and_price: header.excess_blob_gas.map(|excess_blob_gas| {
                BlobExcessGasAndPrice::new(excess_blob_gas, spec >= OpSpecId::ISTHMUS)
            }),
        }
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
    Block(BlockInput<OpEvmFactory>),
    DisputeGame(DisputeGameInput),
}

impl OpEvmInput {
    #[inline]
    pub fn into_env(self, chain_spec: &OpChainSpec) -> EvmEnv<StateDb, OpEvmFactory, Commitment> {
        match self {
            OpEvmInput::Block(input) => input.into_env(chain_spec),
            OpEvmInput::DisputeGame(input) => input.into_env(chain_spec),
        }
    }
}
