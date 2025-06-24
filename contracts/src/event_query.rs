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

/// Event query configuration.
#[derive(Clone)]
#[non_exhaustive]
pub struct EventQueryConfig {
    /// Maximum number of iterations to search for a fulfilled event.
    pub max_iterations: u64,
    /// Number of blocks to query in each iteration when searching for a fulfilled event.
    pub block_range: u64,
}

impl Default for EventQueryConfig {
    fn default() -> Self {
        // Default values chosen based on the docs and pricing of requests on common RPC providers.
        // NOTE: Alchemy free tier applies a limit of 500 block range as of June 24, 2025.
        Self {
            max_iterations: 100,
            block_range: 500,
        }
    }
}

impl EventQueryConfig {
    /// Creates a new event query configuration.
    pub const fn new(max_iterations: u64, block_range: u64) -> Self {
        Self {
            max_iterations,
            block_range,
        }
    }

    /// Sets the maximum number of iterations to search for a fulfilled event.
    pub fn with_max_iterations(self, max_iterations: u64) -> Self {
        Self {
            max_iterations,
            ..self
        }
    }

    /// Sets the number of blocks to query in each iteration when searching for a fulfilled event.
    pub fn with_block_range(self, block_range: u64) -> Self {
        Self {
            block_range,
            ..self
        }
    }
}
