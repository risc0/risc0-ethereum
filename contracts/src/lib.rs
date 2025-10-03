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

// NOTE: Placing the cfg directly on the `pub mod` statement doesn't work when tried with Rust 1.81
cfg_if::cfg_if! {
    if #[cfg(feature = "unstable")] {
        #[cfg(feature = "service")]
        pub mod set_verifier;
        pub mod event_query;
        pub mod receipt;
        pub mod selector;
    }
}

use anyhow::{bail, Result};
use risc0_zkvm::{sha::Digestible, InnerReceipt};

cfg_if::cfg_if! {
    if #[cfg(all(feature = "unstable", feature = "service"))] {
        alloy::sol!(
            #![sol(rpc, all_derives)]
            "src/IRiscZeroVerifier.sol"
        );
        alloy::sol!(
            #![sol(rpc, all_derives)]
            "src/IRiscZeroSetVerifier.sol"
        );
    } else {
        alloy_sol_types::sol!(
            #![sol(all_derives)]
            "src/IRiscZeroVerifier.sol"
        );
        alloy_sol_types::sol!(
            #![sol(all_derives)]
            "src/IRiscZeroSetVerifier.sol"
        );
    }
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
