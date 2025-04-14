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

#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod groth16;

/// Re-export of [alloy], provided to ensure that the correct version of the types used in the
/// public API are available in case multiple versions of [alloy] are in use.
///
/// Because [alloy] is a v0.x crate, it is not covered under the semver policy of this crate.
pub use alloy;

// NOTE: Placing the cfg directly on the `pub mod` statement doesn't work when tried with Rust 1.81
cfg_if::cfg_if! {
    if #[cfg(feature = "unstable")] {
        pub mod set_verifier;
        pub mod event_query;
        pub mod receipt;
        pub mod selector;
    }
}

use core::str::FromStr;

use anyhow::{bail, Result};
use risc0_zkvm::{sha::Digestible, InnerReceipt};

#[cfg(not(target_os = "zkvm"))]
use alloy::{primitives::Bytes, sol_types::SolInterface, transports::TransportError};

alloy::sol!(
    #![sol(rpc, all_derives)]
    "src/IRiscZeroVerifier.sol"
);

alloy::sol!(
    #![sol(rpc, all_derives)]
    "src/IRiscZeroSetVerifier.sol"
);

#[cfg(not(target_os = "zkvm"))]
pub use IRiscZeroSetVerifier::IRiscZeroSetVerifierErrors;

#[cfg(not(target_os = "zkvm"))]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("SetVerifier error: {0:?}")]
    SetVerifierError(IRiscZeroSetVerifierErrors),

    #[error("contract error: {0}")]
    ContractError(alloy::contract::Error),

    #[error("decoding error: {0}")]
    DecodingError(#[from] DecodingError),
}

#[cfg(not(target_os = "zkvm"))]
#[derive(thiserror::Error, Debug)]
pub enum DecodingError {
    #[error("missing data, code: {0} msg: {1}")]
    MissingData(i64, String),

    #[error("error creating bytes from string")]
    BytesFromStrError,

    #[error("abi decoder error: {0} - {1}")]
    Abi(alloy::sol_types::Error, Bytes),
}

/// Encode the seal of the given receipt for use with EVM smart contract verifiers.
///
/// Appends the verifier selector, determined from the first 4 bytes of the verifier parameters
/// including the Groth16 verification key and the control IDs that commit to the RISC Zero
/// circuits.
pub fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>> {
    let seal = match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest().as_bytes().to_vec();
            let selector = &[0xFFu8; 4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            selector_seal
        }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
        // TODO(victor): Add set verifier seal here.
    };
    Ok(seal)
}

#[cfg(not(target_os = "zkvm"))]
fn decode_contract_err<T: SolInterface>(err: alloy::contract::Error) -> Result<T, Error> {
    match err {
        alloy::contract::Error::TransportError(TransportError::ErrorResp(ts_err)) => {
            let Some(data) = ts_err.data else {
                return Err(
                    DecodingError::MissingData(ts_err.code, ts_err.message.to_string()).into(),
                );
            };

            let data = data.get().trim_matches('"');

            let Ok(data) = Bytes::from_str(data) else {
                return Err(DecodingError::BytesFromStrError.into());
            };

            let decoded_error = match T::abi_decode(&data) {
                Ok(res) => res,
                Err(err) => {
                    return Err(DecodingError::Abi(err, data).into());
                }
            };

            Ok(decoded_error)
        }
        _ => Err(Error::ContractError(err)),
    }
}

#[cfg(not(target_os = "zkvm"))]
impl IRiscZeroSetVerifierErrors {
    pub fn decode_error(err: alloy::contract::Error) -> Error {
        match decode_contract_err(err) {
            Ok(res) => Error::SetVerifierError(res),
            Err(decode_err) => decode_err,
        }
    }
}
