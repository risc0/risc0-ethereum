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

use anyhow::{Context, Result};
use risc0_aggregation::{
    decode_seal as decode_set_inclusion_seal, EncodingError, SetInclusionReceipt,
};
use risc0_zkvm::{Receipt as Risc0Receipt, ReceiptClaim};

use crate::{
    encode_seal, groth16,
    selector::{SelecorType, Selector},
};

pub enum ReceiptType {
    Risc0(Risc0Receipt),
    SetInclusion(SetInclusionReceipt<ReceiptClaim>),
}

impl ReceiptType {
    pub fn encode_seal(&self) -> Result<Vec<u8>, EncodingError> {
        match self {
            ReceiptType::Risc0(receipt) => {
                encode_seal(receipt).map_err(|_| EncodingError::UnsupportedReceiptType)
            }
            ReceiptType::SetInclusion(receipt) => receipt.abi_encode_seal(),
        }
    }
}

pub fn decode_seal(
    seal: Vec<u8>,
    claim: ReceiptClaim,
    journal: impl AsRef<[u8]>,
) -> Result<ReceiptType> {
    if seal.len() < 4 {
        return Err(anyhow::anyhow!("seal too short"));
    }
    let selector =
        Selector::from_bytes(seal[..4].try_into().unwrap()).context("decode selector")?;
    let verifier_parameters = selector.verifier_parameters_digest()?;
    match selector.get_type() {
        SelecorType::FakeReceipt => {
            let receipt =
                groth16::decode_seal(seal.into(), claim, journal, Some(verifier_parameters))?;
            Ok(ReceiptType::Risc0(receipt))
        }
        SelecorType::Groth16 => {
            let receipt =
                groth16::decode_seal(seal.into(), claim, journal, Some(verifier_parameters))?;
            Ok(ReceiptType::Risc0(receipt))
        }
        SelecorType::SetVerifier => {
            let receipt = decode_set_inclusion_seal(&seal, claim, verifier_parameters)?;
            Ok(ReceiptType::SetInclusion(receipt))
        }
    }
}
