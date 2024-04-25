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
use crate::ViewCallEnv;

use super::{EvmHeader, ViewCallInput};
use alloy_primitives::{
    keccak256, Address, BlockHash, BlockNumber, Bloom, Bytes, Sealable, B256, B64, U256,
};
use alloy_rlp_derive::RlpEncodable;
use revm::primitives::BlockEnv;
use serde::{Deserialize, Serialize};

/// [ViewCallEnv] for Ethereum.
pub type EthViewCallEnv<D> = ViewCallEnv<D, EthBlockHeader>;

/// [ViewCallInput] for Ethereum.
pub type EthViewCallInput = ViewCallInput<EthBlockHeader>;

/// Ethereum post-merge block header.
#[derive(Debug, Clone, Serialize, Deserialize, RlpEncodable)]
#[rlp(trailing)]
pub struct EthBlockHeader {
    /// Hash of the parent block's header.
    pub parent_hash: BlockHash,
    /// Unused 256-bit hash; always the hash of the empty list.
    pub ommers_hash: B256,
    /// Address that receives the priority fees of each transaction in the block.
    pub beneficiary: Address,
    /// Root hash of the state trie after all transactions in the block are executed.
    pub state_root: B256,
    /// Root hash of the trie containing all transactions in the block.
    pub transactions_root: B256,
    /// Root hash of the trie containing the receipts of each transaction in the block.
    pub receipts_root: B256,
    /// Bloom filter for log entries in the block.
    pub logs_bloom: Bloom,
    /// Always set to `0` as it's unused.
    pub difficulty: U256,
    /// The block number in the chain.
    pub number: BlockNumber,
    /// Maximum amount of gas consumed by the transactions within the block.
    pub gas_limit: u64,
    /// Total amount of gas used by all transactions in this block.
    pub gas_used: u64,
    /// Value corresponding to the seconds since Epoch at this block's inception.
    pub timestamp: u64,
    /// Arbitrary byte array containing extra data related to the block.
    pub extra_data: Bytes,
    /// Hash previously used for the PoW now containing the RANDAO value.
    pub mix_hash: B256,
    /// Unused 64-bit hash, always zero.
    pub nonce: B64,
    /// Base fee paid by all transactions in the block.
    pub base_fee_per_gas: U256,
    /// Root hash of the trie containing all withdrawals in the block.
    pub withdrawals_root: Option<B256>,
    /// Total amount of blob gas consumed by the transactions within the block.
    pub blob_gas_used: Option<u64>,
    /// Running total of blob gas consumed in excess of the target, prior to the block.
    pub excess_blob_gas: Option<u64>,
    /// Hash tree root of the parent beacon block for the given execution block.
    pub parent_beacon_block_root: Option<B256>,
}

impl Sealable for EthBlockHeader {
    #[inline]
    fn hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

impl EvmHeader for EthBlockHeader {
    #[inline]
    fn parent_hash(&self) -> &B256 {
        &self.parent_hash
    }
    #[inline]
    fn number(&self) -> BlockNumber {
        self.number
    }
    #[inline]
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
    #[inline]
    fn state_root(&self) -> &B256 {
        &self.state_root
    }

    #[inline]
    fn fill_block_env(&self, blk_env: &mut BlockEnv) {
        blk_env.number = U256::from(self.number);
        blk_env.coinbase = self.beneficiary;
        blk_env.timestamp = U256::from(self.timestamp);
        blk_env.difficulty = self.difficulty;
        blk_env.prevrandao = Some(self.mix_hash);
        blk_env.basefee = self.base_fee_per_gas;
        blk_env.gas_limit = U256::from(self.gas_limit);
    }
}
