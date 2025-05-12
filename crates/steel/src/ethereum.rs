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

//! Type aliases and specifications for Ethereum.
use crate::{
    config::{ChainSpec, ForkCondition},
    serde::RlpHeader,
    EvmBlockHeader, EvmEnv, EvmFactory, EvmInput,
};
use alloy_evm::{Database, EthEvmFactory as AlloyEthEvmFactory, EvmFactory as AlloyEvmFactory};
use alloy_primitives::{Address, BlockNumber, Bytes, TxKind, B256};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    inspector::NoOpInspector,
    primitives::hardfork::SpecId,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, sync::LazyLock};

/// The Ethereum Sepolia [ChainSpec].
pub static ETH_SEPOLIA_CHAIN_SPEC: LazyLock<EthChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 11155111,
    forks: BTreeMap::from([
        (SpecId::MERGE, ForkCondition::Block(1735371)),
        (SpecId::SHANGHAI, ForkCondition::Timestamp(1677557088)),
        (SpecId::CANCUN, ForkCondition::Timestamp(1706655072)),
        (SpecId::PRAGUE, ForkCondition::Timestamp(1741159776)),
    ]),
});

/// The Ethereum Holešky [ChainSpec].
pub static ETH_HOLESKY_CHAIN_SPEC: LazyLock<EthChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 17000,
    forks: BTreeMap::from([
        (SpecId::MERGE, ForkCondition::Block(0)),
        (SpecId::SHANGHAI, ForkCondition::Timestamp(1696000704)),
        (SpecId::CANCUN, ForkCondition::Timestamp(1707305664)),
        (SpecId::PRAGUE, ForkCondition::Timestamp(1740434112)),
    ]),
});

/// The Ethereum Mainnet [ChainSpec].
pub static ETH_MAINNET_CHAIN_SPEC: LazyLock<EthChainSpec> = LazyLock::new(|| ChainSpec {
    chain_id: 1,
    forks: BTreeMap::from([
        (SpecId::MERGE, ForkCondition::Block(15537394)),
        (SpecId::SHANGHAI, ForkCondition::Timestamp(1681338455)),
        (SpecId::CANCUN, ForkCondition::Timestamp(1710338135)),
        (SpecId::PRAGUE, ForkCondition::Timestamp(1746612311)),
    ]),
});

/// [EvmFactory] for Ethereum.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EthEvmFactory;

impl EvmFactory for EthEvmFactory {
    type Evm<DB: Database> = <AlloyEthEvmFactory as AlloyEvmFactory>::Evm<DB, NoOpInspector>;
    type Tx = <AlloyEthEvmFactory as AlloyEvmFactory>::Tx;
    type Error<DBError: Error + Send + Sync + 'static> =
        <AlloyEthEvmFactory as AlloyEvmFactory>::Error<DBError>;
    type HaltReason = <AlloyEthEvmFactory as AlloyEvmFactory>::HaltReason;
    type Spec = <AlloyEthEvmFactory as AlloyEvmFactory>::Spec;
    type Header = EthBlockHeader;

    fn new_tx(address: Address, data: Bytes) -> Self::Tx {
        TxEnv {
            caller: address,
            kind: TxKind::Call(address),
            data,
            chain_id: None,
            ..Default::default()
        }
    }

    fn create_evm<DB: Database>(
        db: DB,
        chain_id: u64,
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

        AlloyEthEvmFactory::default().create_evm(db, (cfg_env, block_env).into())
    }
}

/// [ChainSpec] for Ethereum.
pub type EthChainSpec = ChainSpec<SpecId>;

/// [EvmEnv] for Ethereum.
pub type EthEvmEnv<D, C> = EvmEnv<D, EthEvmFactory, C>;

/// [EvmInput] for Ethereum.
pub type EthEvmInput = EvmInput<EthEvmFactory>;

/// [EvmBlockHeader] for Ethereum.
pub type EthBlockHeader = RlpHeader<alloy_consensus::Header>;

impl EvmBlockHeader for EthBlockHeader {
    type Spec = SpecId;

    #[inline]
    fn parent_hash(&self) -> &B256 {
        &self.inner().parent_hash
    }
    #[inline]
    fn number(&self) -> BlockNumber {
        self.inner().number
    }
    #[inline]
    fn timestamp(&self) -> u64 {
        self.inner().timestamp
    }
    #[inline]
    fn state_root(&self) -> &B256 {
        &self.inner().state_root
    }
    #[inline]
    fn receipts_root(&self) -> &B256 {
        &self.inner().receipts_root
    }
    #[inline]
    fn logs_bloom(&self) -> &alloy_primitives::Bloom {
        &self.inner().logs_bloom
    }

    #[inline]
    fn to_block_env(&self, spec: SpecId) -> BlockEnv {
        let header = self.inner();

        BlockEnv {
            number: header.number,
            beneficiary: header.beneficiary,
            timestamp: header.timestamp,
            gas_limit: header.gas_limit,
            basefee: header.base_fee_per_gas.unwrap_or_default(),
            difficulty: header.difficulty,
            prevrandao: (spec >= SpecId::MERGE).then_some(header.mix_hash),
            blob_excess_gas_and_price: header.excess_blob_gas.map(|excess_blob_gas| {
                BlobExcessGasAndPrice::new(excess_blob_gas, spec >= SpecId::PRAGUE)
            }),
        }
    }
}
