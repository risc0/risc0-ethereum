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

//! Handling different blockchain specifications.
use alloy_primitives::{BlockNumber, BlockTimestamp, ChainId, B256};
use anyhow::bail;
use serde::{Deserialize, Serialize};
use sha2::{digest::Output, Digest, Sha256};
use std::collections::BTreeMap;

/// The condition at which a fork is activated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkCondition {
    /// The fork is activated with a certain block.
    Block(BlockNumber),
    /// The fork is activated with a specific timestamp.
    Timestamp(BlockTimestamp),
}

impl ForkCondition {
    /// Returns whether the condition has been met.
    #[inline]
    pub fn active(&self, block_number: BlockNumber, timestamp: u64) -> bool {
        match self {
            ForkCondition::Block(block) => *block <= block_number,
            ForkCondition::Timestamp(ts) => *ts <= timestamp,
        }
    }
}

/// Specification of a specific chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSpec<S: ToString + Ord> {
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Map revm specification IDs to their respective activation condition.
    pub forks: BTreeMap<S, ForkCondition>,
}

impl<S: ToString + std::cmp::Ord + Default> Default for ChainSpec<S> {
    /// Defaults to Ethereum Chain ID using the latest specification.
    #[inline]
    fn default() -> Self {
        Self::new_single(1, S::default())
    }
}

impl<S: ToString + std::cmp::Ord> ChainSpec<S> {
    /// Creates a new configuration consisting of only one specification ID.
    ///
    /// For example, this can be used to create a [ChainSpec] for an anvil instance:
    /// ```rust
    /// # use revm::primitives::hardfork::SpecId;
    /// # use risc0_steel::config::ChainSpec;
    /// let spec = ChainSpec::new_single(31337, SpecId::CANCUN);
    /// ```
    pub fn new_single(chain_id: ChainId, spec_id: S) -> Self {
        ChainSpec {
            chain_id,
            forks: BTreeMap::from([(spec_id, ForkCondition::Block(0))]),
        }
    }

    /// Returns the network chain ID.
    #[inline]
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Returns the cryptographic digest of the entire network configuration.
    #[inline]
    pub fn digest(&self) -> B256 {
        <[u8; 32]>::from(StructHash::digest::<Sha256>(self)).into()
    }

    /// Returns the spec for a given block number and timestamp or an error if not supported.
    pub fn active_fork(&self, block_number: BlockNumber, timestamp: u64) -> anyhow::Result<&S> {
        for (spec_id, fork) in self.forks.iter().rev() {
            if fork.active(block_number, timestamp) {
                return Ok(spec_id);
            }
        }
        bail!("no supported fork for block {}", block_number)
    }
}

// NOTE: We do not want to make this public, to avoid having multiple traits with the `digest`
// function in the RISC Zero ecosystem of crates.
/// A simple structured hasher.
trait StructHash {
    fn digest<D: Digest>(&self) -> Output<D>;
}

impl<S: ToString> StructHash for (&S, &ForkCondition) {
    /// Computes the cryptographic digest of a fork.
    /// The hash is H(SpecName || ForkCondition::name || ForkCondition::value )
    fn digest<D: Digest>(&self) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(self.0.to_string());
        match self.1 {
            ForkCondition::Block(n) => {
                hasher.update(b"Block");
                hasher.update(n.to_le_bytes());
            }
            ForkCondition::Timestamp(ts) => {
                hasher.update(b"Timestamp");
                hasher.update(ts.to_le_bytes());
            }
        }
        hasher.finalize()
    }
}

impl<S: ToString + std::cmp::Ord> StructHash for ChainSpec<S> {
    /// Computes the cryptographic digest of a chain spec.
    ///
    /// This is equivalent to the `tagged_struct` structural hashing routines used for RISC Zero
    /// data structures:
    /// `tagged_struct("ChainSpec(chain_id,forks)", forks.into_vec(), &[chain_id, chain_id >> 32])`
    fn digest<D: Digest>(&self) -> Output<D> {
        let tag_digest = D::digest(b"ChainSpec(chain_id,forks)");

        let mut hasher = D::new();
        hasher.update(tag_digest);
        // down
        self.forks
            .iter()
            .for_each(|fork| hasher.update(fork.digest::<D>()));
        // data
        hasher.update(self.chain_id.to_le_bytes());
        // down.len() as u16
        hasher.update(u16::try_from(self.forks.len()).unwrap().to_le_bytes());

        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum::EthChainSpec;
    use revm::primitives::hardfork::SpecId;

    #[test]
    fn active_fork() {
        let spec = ChainSpec {
            chain_id: 1,
            forks: BTreeMap::from([
                (SpecId::MERGE, ForkCondition::Block(2)),
                (SpecId::CANCUN, ForkCondition::Timestamp(60)),
            ]),
        };

        assert!(spec.active_fork(0, 0).is_err());
        assert_eq!(*spec.active_fork(2, 0).unwrap(), SpecId::MERGE);
        assert_eq!(*spec.active_fork(u64::MAX, 59).unwrap(), SpecId::MERGE);
        assert_eq!(*spec.active_fork(0, 60).unwrap(), SpecId::CANCUN);
        assert_eq!(
            *spec.active_fork(u64::MAX, u64::MAX).unwrap(),
            SpecId::CANCUN
        );
    }

    #[test]
    fn default_digest() {
        let exp: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(Sha256::digest(b"ChainSpec(chain_id,forks)"));
            h.update((&SpecId::default(), &ForkCondition::Block(0)).digest::<Sha256>());
            h.update((1u64 as u32).to_le_bytes());
            h.update(((1u64 >> 32) as u32).to_le_bytes());
            h.update(1u16.to_le_bytes());
            h.finalize().into()
        };
        assert_eq!(EthChainSpec::DEFAULT_DIGEST, B256::from(exp));
        assert_eq!(EthChainSpec::default().digest(), B256::from(exp));
    }
}
