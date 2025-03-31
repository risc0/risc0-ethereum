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

use std::fmt::{self, Display, Formatter};

use hex::FromHex;
use risc0_zkvm::sha::Digest;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SelectorError {
    #[error("Unsupported selector")]
    UnsupportedSelector,
    #[error("Selector {0} does not have verifier parameters")]
    NoVerifierParameters(Selector),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectorType {
    FakeReceipt,
    Groth16,
    SetVerifier,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Selector {
    FakeReceipt = 0xFFFFFFFF,
    Groth16V1_1 = 0x50bd1769,
    Groth16V1_2 = 0xc101b42b,
    Groth16V2_0 = 0x9f39696c,
    SetVerifierV0_1 = 0xbfca9ccb,
    SetVerifierV0_2 = 0x16a15cc8,
    SetVerifierV0_4 = 0xf443ad7b,
}

impl Display for Selector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", *self as u32)
    }
}

impl TryFrom<u32> for Selector {
    type Error = SelectorError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0xFFFFFFFF => Ok(Selector::FakeReceipt),
            0x50bd1769 => Ok(Selector::Groth16V1_1),
            0xc101b42b => Ok(Selector::Groth16V1_2),
            0x9f39696c => Ok(Selector::Groth16V2_0),
            0xbfca9ccb => Ok(Selector::SetVerifierV0_1),
            0x16a15cc8 => Ok(Selector::SetVerifierV0_2),
            0xf443ad7b => Ok(Selector::SetVerifierV0_4),
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
            Selector::Groth16V2_0 => Ok(Digest::from_hex(
                "9f39696cb3ae9d6038d6b7a55c09017f0cf35e226ad7582b82dbabb0dae53385",
            )
            .unwrap()),
            Selector::SetVerifierV0_1 => Ok(Digest::from_hex(
                "bfca9ccb59eb38b8c78ddc399a734d8e0e84e8028b7d616fa54fe707a1ff1b3b",
            )
            .unwrap()),
            Selector::SetVerifierV0_2 => Ok(Digest::from_hex(
                "16a15cc8c94a59dc3e4e41226bc560ecda596a371a487b7ecc6b65d9516dfbdb",
            )
            .unwrap()),
            Selector::SetVerifierV0_4 => Ok(Digest::from_hex(
                "f443ad7bfe538ec90fa38498afd30b27b7d06336f20249b620a6d85ab3c615b6",
            )
            .unwrap()),
        }
    }

    pub fn get_type(self) -> SelectorType {
        match self {
            Selector::FakeReceipt => SelectorType::FakeReceipt,
            Selector::Groth16V1_1 | Selector::Groth16V1_2 | Selector::Groth16V2_0 => {
                SelectorType::Groth16
            }
            Selector::SetVerifierV0_1 | Selector::SetVerifierV0_2 | Selector::SetVerifierV0_4 => {
                SelectorType::SetVerifier
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Option<Self> {
        Self::try_from(u32::from_be_bytes(bytes)).ok()
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use risc0_aggregation::SetInclusionReceiptVerifierParameters;
    use risc0_zkvm::{
        sha::{Digest, Digestible},
        Groth16ReceiptVerifierParameters,
    };

    // SetBuilder image ID v0.4.0 (built using cargo risczero build v2.0.0)
    const SET_BUILDER_ID: &str = "8888bf20b2be0ca935e166325578c336cc16355f9b63e7e5279c71a0a97f4df9";

    #[test]
    fn print_verifier_parameters() {
        let digest = Groth16ReceiptVerifierParameters::default().digest();
        println!("Groth16ReceiptVerifierParameters {}", digest);

        let digest = SetInclusionReceiptVerifierParameters {
            image_id: Digest::from_hex(SET_BUILDER_ID).unwrap(),
        }
        .digest();
        println!("SetInclusionReceiptVerifierParameters {}", digest);
    }
}
