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

use alloy_primitives::{Address, B256};
use alloy_sol_types::{sol, SolStruct};
use risc0_steel::SolCommitment;
use serde::{Deserialize, Serialize};

#[cfg(not(target_os = "zkvm"))]
pub mod contracts;

sol! {
    interface IL1CrossDomainMessenger {
        /// Returns whether the digest of the message has been committed to be relayed.
        function contains(bytes32 digest) external view returns (bool);
    }
}

sol! {
    /// A Message to be relayed.
    #[derive(Serialize, Deserialize)]
    struct Message {
        address target;
        address sender;
        bytes data;
        uint256 nonce;
    }

    /// Journal returned by the guest.
    struct Journal {
        SolCommitment commitment;
        address l1CrossDomainMessenger;
        Message message;
        bytes32 messageDigest;
    }
}

impl Message {
    #[inline]
    pub fn digest(&self) -> B256 {
        return self.eip712_hash_struct();
    }
}

#[derive(Serialize, Deserialize)]
pub struct CrossDomainMessengerInput {
    pub l1_cross_domain_messenger: Address,
    pub message: Message,
}

impl CrossDomainMessengerInput {
    /// Converts the input into the corresponding [Journal], leaving the commitment empty.
    #[inline]
    pub fn into_journal(self) -> Journal {
        let digest = self.message.digest();

        Journal {
            commitment: SolCommitment::default(),
            l1CrossDomainMessenger: self.l1_cross_domain_messenger,
            message: self.message,
            messageDigest: digest,
        }
    }
}
