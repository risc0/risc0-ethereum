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
use risc0_steel::Commitment;
use serde::{Deserialize, Serialize};

sol!("../../contracts/src/IL1CrossDomainMessenger.sol");

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
        Commitment commitment;
        address l1CrossDomainMessenger;
        Message message;
        bytes32 messageDigest;
    }
}

impl Message {
    #[inline]
    pub fn digest(&self) -> B256 {
        self.eip712_hash_struct()
    }
}

impl From<IL1CrossDomainMessenger::SentMessage> for Message {
    fn from(event: IL1CrossDomainMessenger::SentMessage) -> Self {
        Self {
            target: event.target,
            sender: event.sender,
            data: event.data,
            nonce: event.messageNonce,
        }
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
            commitment: Commitment::default(),
            l1CrossDomainMessenger: self.l1_cross_domain_messenger,
            message: self.message,
            messageDigest: digest,
        }
    }
}
