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

use super::rlp::RlpNode;

pub(super) trait Memoization: Default {
    fn clear(&mut self);
    fn get(&self) -> Option<&RlpNode>;
    fn set(&mut self, rlp_node: RlpNode);
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct NoCache;

impl Memoization for NoCache {
    #[inline]
    fn clear(&mut self) {}
    #[inline]
    fn get(&self) -> Option<&RlpNode> {
        None
    }
    #[inline]
    fn set(&mut self, _: RlpNode) {}
}

#[derive(Debug, Clone, Default)]
pub(super) struct Cache(Option<RlpNode>);

impl Memoization for Cache {
    #[inline]
    fn clear(&mut self) {
        self.0 = None
    }
    #[inline]
    fn get(&self) -> Option<&RlpNode> {
        self.0.as_ref()
    }
    #[inline]
    fn set(&mut self, rlp_node: RlpNode) {
        self.0 = Some(rlp_node)
    }
}
