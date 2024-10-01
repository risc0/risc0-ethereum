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

//! Handling different blockchain specifications.
use std::collections::BTreeMap;

use alloy_primitives::{BlockNumber, ChainId};
use anyhow::bail;
use revm::primitives::SpecId;
use serde::{Deserialize, Serialize};

/// The condition at which a fork is activated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ForkCondition {
    /// The fork is activated with a certain block.
    Block(BlockNumber),
    /// The fork is activated with a specific timestamp.
    Timestamp(u64),
    /// The fork is never activated
    #[default]
    TBD,
}

impl ForkCondition {
    /// Returns whether the condition has been met.
    #[inline]
    pub fn active(&self, block_number: BlockNumber, timestamp: u64) -> bool {
        match self {
            ForkCondition::Block(block) => *block <= block_number,
            ForkCondition::Timestamp(ts) => *ts <= timestamp,
            ForkCondition::TBD => false,
        }
    }
}

/// Specification of a specific chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSpec {
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Map revm specification IDs to their respective activation condition.
    pub forks: BTreeMap<SpecId, ForkCondition>,
}

impl ChainSpec {
    /// Creates a new configuration consisting of only one specification ID.
    ///
    /// For example, this can be used to create a [ChainSpec] for an anvil instance:
    /// ```rust
    /// # use revm::primitives::SpecId;
    /// # use risc0_steel::config::ChainSpec;
    /// let spec = ChainSpec::new_single(31337, SpecId::CANCUN);
    /// ```
    pub fn new_single(chain_id: ChainId, spec_id: SpecId) -> Self {
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

    /// Returns the [SpecId] for a given block number and timestamp or an error if not supported.
    pub fn active_fork(&self, block_number: BlockNumber, timestamp: u64) -> anyhow::Result<SpecId> {
        for (spec_id, fork) in self.forks.iter().rev() {
            if fork.active(block_number, timestamp) {
                return Ok(*spec_id);
            }
        }
        bail!("no supported fork for block {}", block_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_fork() {
        let spec = ChainSpec {
            chain_id: 1,
            forks: BTreeMap::from([
                (SpecId::MERGE, ForkCondition::Block(2)),
                (SpecId::CANCUN, ForkCondition::Timestamp(60)),
                (SpecId::PRAGUE, ForkCondition::TBD),
            ]),
        };

        assert!(spec.active_fork(0, 0).is_err());
        assert_eq!(spec.active_fork(2, 0).unwrap(), SpecId::MERGE);
        assert_eq!(spec.active_fork(u64::MAX, 59).unwrap(), SpecId::MERGE);
        assert_eq!(spec.active_fork(0, 60).unwrap(), SpecId::CANCUN);
        assert_eq!(
            spec.active_fork(u64::MAX, u64::MAX).unwrap(),
            SpecId::CANCUN
        );
    }
}
