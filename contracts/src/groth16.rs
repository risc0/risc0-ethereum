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

use alloy_sol_types::SolValue;
use anyhow::Result;
use risc0_zkvm::{sha::Digestible, Groth16ReceiptVerifierParameters};

/// ABI encoding of the seal.
pub fn abi_encode(seal: Vec<u8>) -> Result<Vec<u8>> {
    Ok(encode(seal)?.abi_encode())
}

/// encoding of the seal with selector.
pub fn encode(seal: Vec<u8>) -> Result<Vec<u8>> {
    let verifier_parameters_digest = Groth16ReceiptVerifierParameters::default().digest();
    let selector = &verifier_parameters_digest.as_bytes()[..4];
    // Create a new vector with the capacity to hold both selector and seal
    let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
    selector_seal.extend_from_slice(selector);
    selector_seal.extend_from_slice(&seal);

    Ok(selector_seal)
}
