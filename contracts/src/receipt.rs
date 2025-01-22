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

use alloy_primitives::Bytes;
use risc0_aggregation::{
    decode_set_inclusion_seal, SetInclusionDecodingError, SetInclusionEncodingError,
    SetInclusionReceipt,
};
use risc0_zkvm::{FakeReceipt, InnerReceipt, Receipt as Risc0Receipt, ReceiptClaim};
use thiserror::Error;

use crate::{
    encode_seal,
    groth16::decode_groth16_seal,
    selector::{SelecorType, Selector, SelectorError},
};

/// Wrapper around different types of receipts.
pub enum ReceiptType {
    Risc0(Risc0Receipt),
    SetInclusion(SetInclusionReceipt<ReceiptClaim>),
}

impl ReceiptType {
    /// Encode the receipt as a seal.
    pub fn encode_seal(&self) -> Result<Vec<u8>, SetInclusionEncodingError> {
        match self {
            ReceiptType::Risc0(receipt) => {
                encode_seal(receipt).map_err(|_| SetInclusionEncodingError::UnsupportedReceiptType)
            }
            ReceiptType::SetInclusion(receipt) => receipt.abi_encode_seal(),
        }
    }

    /// Get the receipt if it is a RISC0 receipt.
    pub fn receipt(&self) -> Option<Risc0Receipt> {
        match self {
            ReceiptType::Risc0(receipt) => Some(receipt.clone()),
            _ => None,
        }
    }

    /// Get the receipt if it is a set inclusion receipt.
    pub fn set_inclusion_receipt(&self) -> Option<&SetInclusionReceipt<ReceiptClaim>> {
        match self {
            ReceiptType::SetInclusion(receipt) => Some(receipt),
            _ => None,
        }
    }
}

/// Errors that can occur when decoding a seal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecodingError {
    #[error("Seal too short")]
    SealTooShort,
    #[error("Unsupported selector {0:?}")]
    UnsupportedSelector([u8; 4]),
    #[error("Selector error: {0}")]
    SelectorError(#[from] SelectorError),
    #[error("Decoding error: {0}")]
    SetInclusionError(#[from] SetInclusionDecodingError),
    #[error("Decoding error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

/// Decode a seal into a receipt.
pub fn decode_seal(
    seal: Bytes,
    claim: ReceiptClaim,
    journal: impl AsRef<[u8]>,
) -> Result<ReceiptType, DecodingError> {
    if seal.len() < 4 {
        return Err(DecodingError::SealTooShort);
    }
    let selector = [seal[0], seal[1], seal[2], seal[3]];
    let selector = Selector::from_bytes(selector)
        .ok_or_else(|| DecodingError::UnsupportedSelector(selector))?;
    let verifier_parameters = selector.verifier_parameters_digest()?;
    match selector.get_type() {
        SelecorType::FakeReceipt => {
            let receipt = Risc0Receipt::new(
                InnerReceipt::Fake(FakeReceipt::new(claim)),
                journal.as_ref().to_vec(),
            );
            Ok(ReceiptType::Risc0(receipt))
        }
        SelecorType::Groth16 => {
            let receipt = decode_groth16_seal(seal, claim, journal, Some(verifier_parameters))?;
            Ok(ReceiptType::Risc0(receipt))
        }
        SelecorType::SetVerifier => {
            let receipt = decode_set_inclusion_seal(&seal, claim, verifier_parameters)?;
            Ok(ReceiptType::SetInclusion(receipt))
        }
    }
}
