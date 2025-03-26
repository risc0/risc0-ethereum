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
use risc0_zkvm::{sha::Digest, FakeReceipt, InnerReceipt, ReceiptClaim};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    encode_seal,
    groth16::decode_groth16_seal,
    selector::{Selector, SelectorError, SelectorType},
};

/// Extension of the base [risc0_zkvm::Receipt] type.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Receipt {
    Base(Box<risc0_zkvm::Receipt>),
    SetInclusion(Box<SetInclusionReceipt<ReceiptClaim>>),
}

impl Receipt {
    /// Encode the receipt as a seal.
    pub fn abi_encode_seal(&self) -> Result<Vec<u8>, SetInclusionEncodingError> {
        match self {
            Receipt::Base(receipt) => {
                encode_seal(receipt).map_err(|_| SetInclusionEncodingError::UnsupportedReceipt)
            }
            Receipt::SetInclusion(receipt) => receipt.abi_encode_seal(),
        }
    }

    /// Get the receipt if it is a base [risc0_zkvm::Receipt].
    pub fn receipt(&self) -> Option<&risc0_zkvm::Receipt> {
        match self {
            Receipt::Base(receipt) => Some(receipt),
            _ => None,
        }
    }

    /// Get the receipt if it is a set inclusion receipt.
    pub fn set_inclusion_receipt(&self) -> Option<&SetInclusionReceipt<ReceiptClaim>> {
        match self {
            Receipt::SetInclusion(receipt) => Some(receipt),
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
    image_id: impl Into<Digest>,
    journal: impl Into<Vec<u8>>,
) -> Result<Receipt, DecodingError> {
    let journal = journal.into();
    let claim = ReceiptClaim::ok(image_id, journal.clone());
    decode_seal_with_claim(seal, claim, journal)
}

/// Decode a seal into a receipt.
pub fn decode_seal_with_claim(
    seal: Bytes,
    claim: ReceiptClaim,
    journal: impl Into<Vec<u8>>,
) -> Result<Receipt, DecodingError> {
    if seal.len() < 4 {
        return Err(DecodingError::SealTooShort);
    }
    let selector = [seal[0], seal[1], seal[2], seal[3]];
    let selector = Selector::from_bytes(selector)
        .ok_or_else(|| DecodingError::UnsupportedSelector(selector))?;
    match selector.get_type() {
        SelectorType::FakeReceipt => {
            let receipt = risc0_zkvm::Receipt::new(
                InnerReceipt::Fake(FakeReceipt::new(claim)),
                journal.into(),
            );
            Ok(Receipt::Base(Box::new(receipt)))
        }
        SelectorType::Groth16 => {
            let verifier_parameters = selector.verifier_parameters_digest()?;
            let receipt =
                decode_groth16_seal(seal, claim, journal.into(), Some(verifier_parameters))?;
            Ok(Receipt::Base(Box::new(receipt)))
        }
        SelectorType::SetVerifier => {
            let verifier_parameters = selector.verifier_parameters_digest()?;
            let receipt = decode_set_inclusion_seal(&seal, claim, verifier_parameters)?;
            Ok(Receipt::SetInclusion(Box::new(receipt)))
        }
    }
}
