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
    /// ID of the latest supported revm specification.
    pub max_spec_id: SpecId,
    /// Map revm specification IDs to their respective activation condition.
    pub hard_forks: BTreeMap<SpecId, ForkCondition>,
}

impl ChainSpec {
    /// Creates a new configuration consisting of only one specification ID.
    pub fn new_single(chain_id: ChainId, spec_id: SpecId) -> Self {
        ChainSpec {
            chain_id,
            max_spec_id: spec_id,
            hard_forks: BTreeMap::from([(spec_id, ForkCondition::Block(0))]),
        }
    }
    /// Returns the network chain ID.
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    /// Validates a [SpecId].
    pub fn validate_spec_id(&self, spec_id: SpecId) -> anyhow::Result<()> {
        let (min_spec_id, _) = self.hard_forks.first_key_value().unwrap();
        if spec_id < *min_spec_id {
            bail!("expected >= {:?}, got {:?}", min_spec_id, spec_id);
        }
        if spec_id > self.max_spec_id {
            bail!("expected <= {:?}, got {:?}", self.max_spec_id, spec_id);
        }
        Ok(())
    }
    /// Returns the [SpecId] for a given block number and timestamp or an error if not
    /// supported.
    pub fn active_fork(&self, block_number: BlockNumber, timestamp: u64) -> anyhow::Result<SpecId> {
        match self.spec_id(block_number, timestamp) {
            Some(spec_id) => {
                if spec_id > self.max_spec_id {
                    bail!("expected <= {:?}, got {:?}", self.max_spec_id, spec_id);
                } else {
                    Ok(spec_id)
                }
            }
            None => bail!("no supported fork for block {}", block_number),
        }
    }

    fn spec_id(&self, block_number: BlockNumber, timestamp: u64) -> Option<SpecId> {
        for (spec_id, fork) in self.hard_forks.iter().rev() {
            if fork.active(block_number, timestamp) {
                return Some(*spec_id);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use once_cell::sync::Lazy;

    static ETH_MAINNET_CHAIN_SPEC: Lazy<ChainSpec> = Lazy::new(|| ChainSpec {
        chain_id: 1,
        max_spec_id: SpecId::CANCUN,
        hard_forks: BTreeMap::from([
            (SpecId::MERGE, ForkCondition::Block(15537394)),
            (SpecId::SHANGHAI, ForkCondition::Timestamp(1681338455)),
            (SpecId::CANCUN, ForkCondition::Timestamp(1710338135)),
        ]),
    });

    #[test]
    fn spec_id() {
        assert_eq!(ETH_MAINNET_CHAIN_SPEC.spec_id(15537393, 0), None);
        assert_eq!(
            ETH_MAINNET_CHAIN_SPEC.spec_id(15537394, 0),
            Some(SpecId::MERGE)
        );
        assert_eq!(
            ETH_MAINNET_CHAIN_SPEC.spec_id(17034869, 0),
            Some(SpecId::MERGE)
        );
        assert_eq!(
            ETH_MAINNET_CHAIN_SPEC.spec_id(0, 1681338455),
            Some(SpecId::SHANGHAI)
        );
    }
}
