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

use hex::FromHex;
use risc0_zkvm::sha::Digest;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SelectorError {
    #[error("Unsupported selector")]
    UnsupportedSelector,
    #[error("Selector (0) does not have verifier parameters")]
    NoVerifierParameters(Selector),
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Selector {
    FakeReceipt = 0x00000000,
    Groth16V1_1 = 0x50bd1769,
    Groth16V1_2 = 0xc101b42b,
    SetVerifierV0_1 = 0xbfca9ccb,
}

impl TryFrom<u32> for Selector {
    type Error = SelectorError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x00000000 => Ok(Selector::FakeReceipt),
            0x50bd1769 => Ok(Selector::Groth16V1_1),
            0xc101b42b => Ok(Selector::Groth16V1_2),
            0xbfca9ccb => Ok(Selector::SetVerifierV0_1),
            _ => Err(SelectorError::UnsupportedSelector),
        }
    }
}

impl Selector {
    pub fn verifier_parameters_digest(self) -> Result<Digest, SelectorError> {
        match self {
            Selector::FakeReceipt => {
                Err(SelectorError::NoVerifierParameters(Selector::FakeReceipt))
            }
            Selector::Groth16V1_1 => Ok(Digest::from_hex(
                "50bd1769093e74abda3711c315d84d78e3e282173f6304a33272d92abb590ef5",
            )
            .unwrap()),
            Selector::Groth16V1_2 => Ok(Digest::from_hex(
                "c101b42bcacd62e35222b1207223250814d05dd41d41f8cadc1f16f86707ae15",
            )
            .unwrap()),
            Selector::SetVerifierV0_1 => Ok(Digest::from_hex(
                "bfca9ccb59eb38b8c78ddc399a734d8e0e84e8028b7d616fa54fe707a1ff1b3b",
            )
            .unwrap()),
        }
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Option<Self> {
        Self::try_from(u32::from_be_bytes(bytes)).ok()
    }
}
