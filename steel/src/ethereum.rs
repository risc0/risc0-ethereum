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

//! Type aliases for Ethereum.
use crate::{serde::RlpHeader, EvmEnv};

use super::{EvmBlockHeader, EvmInput};
use alloy_primitives::{BlockNumber, B256, U256};
use revm::primitives::BlockEnv;

/// [EvmEnv] for Ethereum.
pub type EthEvmEnv<D> = EvmEnv<D, EthBlockHeader>;

/// [EvmInput] for Ethereum.
pub type EthEvmInput = EvmInput<EthBlockHeader>;

/// [EvmBlockHeader] for Ethereum.
pub type EthBlockHeader = RlpHeader<alloy_consensus::Header>;

impl EvmBlockHeader for EthBlockHeader {
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
    fn fill_block_env(&self, blk_env: &mut BlockEnv) {
        let header = self.inner();

        blk_env.number = U256::from(header.number);
        blk_env.coinbase = header.beneficiary;
        blk_env.timestamp = U256::from(header.timestamp);
        blk_env.gas_limit = U256::from(header.gas_limit);
        blk_env.basefee = U256::from(header.base_fee_per_gas.unwrap_or_default());
        blk_env.difficulty = header.difficulty;
        // technically, this is only valid after EIP-4399 but revm makes sure it is not used before
        blk_env.prevrandao = Some(header.mix_hash);
        if let Some(excess_blob_gas) = header.excess_blob_gas {
            blk_env.set_blob_excess_gas_and_price(excess_blob_gas.try_into().unwrap())
        };
    }
}
