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

use alloc::vec::Vec;

use alloy_primitives::B256;
use alloy_sol_types::SolValue;
use risc0_binfmt::{tagged_struct, Digestible};
use risc0_zkvm::{
    sha,
    sha::{Digest, Sha256, DIGEST_BYTES},
    InnerReceipt, MaybePruned, Receipt, ReceiptClaim, VerifierContext,
};
use serde::{Deserialize, Serialize};

use crate::{merkle_path_root, GuestState, MerkleMountainRange, Seal};

// TODO(#353)
//pub use guest_set_builder::{SET_BUILDER_ELF, SET_BUILDER_ID, SET_BUILDER_PATH};

/// A receipt for a claim that is part of a set of verified claims (i.e. an aggregation).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SetInclusionReceipt<Claim>
where
    Claim: Digestible + Clone + Serialize,
{
    /// Claim containing information about the computation that this receipt proves.
    ///
    /// The standard claim type is [ReceiptClaim], which represents a RISC-V
    /// zkVM execution.
    pub claim: MaybePruned<Claim>,

    /// Root receipt attesting to the validity of all claims included in the set committed to by
    /// the Merkle root in the journal of this receipt. It is required that this receipt was
    /// produced by running the aggregation set builder, which verifies each receipt before adding
    /// it to the set represented by a Merkle tree.
    ///
    /// In certain contexts, the root claim can be omitted. In particular, the zkVM guest can
    /// verify the root by making an assumption (i.e. by calling `env::verify`), and verifies in an
    /// EVM context may reference previously proven claims via a verification cache in storage.
    pub root: Option<Receipt>,

    /// Merkle proof for inclusion in the set of claims attested to by the root receipt.
    pub merkle_path: Vec<Digest>,

    /// A digest of the verifier parameters that can be used to verify this receipt.
    ///
    /// Acts as a fingerprint to identify differing proof system or circuit versions between a
    /// prover and a verifier. Is not intended to contain the full verifier parameters, which must
    /// be provided by a trusted source (e.g. packaged with the verifier code).
    pub verifier_parameters: Digest,
}

#[derive(thiserror::Error, Debug)]
pub enum VerificationError {
    #[error("{0}")]
    Base(risc0_zkp::verify::VerificationError),
    #[error("root receipt claim does not match expected set builder claim: {claim_digest} != {expected}")]
    ClaimDigestDoesNotMatch {
        claim_digest: Digest,
        expected: Digest,
    },
    #[error("failed to confirm the validity of the set root: {path_root}")]
    RootNotVerified { path_root: Digest },
}

impl From<core::convert::Infallible> for VerificationError {
    fn from(_: core::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl From<risc0_zkp::verify::VerificationError> for VerificationError {
    fn from(err: risc0_zkp::verify::VerificationError) -> Self {
        VerificationError::Base(err)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SetInclusionEncodingError {
    #[error("unsupported receipt type")]
    UnsupportedReceipt,
}

#[derive(thiserror::Error, Debug)]
pub enum SetInclusionDecodingError {
    #[error("unsupported receipt type")]
    UnsupportedReceipt,
    #[error("Digest decoding error")]
    Digest,
    #[error("failed to decode aggregation seal from bytes")]
    SolType(#[from] alloy_sol_types::Error),
}

impl<Claim> SetInclusionReceipt<Claim>
where
    Claim: Digestible + Clone + Serialize,
{
    /* TODO(#353)
    /// Construct a [SetInclusionReceipt] with the given Merkle inclusion path and claim.
    ///
    /// Path should contain all sibling nodes in the tree from the leaf to the root. Note that the
    /// path does not include the leaf or the root itself. Resulting receipt will have default
    /// verifier parameters and no root receipt.
    pub fn from_path(claim: impl Into<MaybePruned<Claim>>, merkle_path: Vec<Digest>);
    }
    */

    /// Construct a [SetInclusionReceipt] with the given Merkle inclusion path and claim.
    ///
    /// Path should contain all sibling nodes in the tree from the leaf to the root. Note that the
    /// path does not include the leaf or the root itself. Resulting receipt will have the given
    /// verifier parameter digest and no root receipt.
    pub fn from_path_with_verifier_params(
        claim: impl Into<MaybePruned<Claim>>,
        merkle_path: Vec<Digest>,
        verifier_parameters: impl Into<Digest>,
    ) -> Self {
        Self {
            claim: claim.into(),
            root: None,
            merkle_path,
            verifier_parameters: verifier_parameters.into(),
        }
    }

    /// Add the given root receipt to this set inclusion receipt.
    ///
    /// See [SetInclusionReceipt::root] for more information about the root receipt.
    pub fn with_root(self, root_receipt: Receipt) -> Self {
        Self {
            root: Some(root_receipt),
            ..self
        }
    }

    /// Drops the root receipt from this [SetInclusionReceipt].
    ///
    /// This is useful when the verifier has a cache of verified roots, as is the case for smart
    /// contract verifiers. Use this method when submitting this receipt as part of a batch of
    /// receipts to be verified, to reduce the encoded size of this receipt.
    pub fn without_root(self) -> Self {
        Self { root: None, ..self }
    }

    /* TODO(#353)
    /// Verify the integrity of this receipt, ensuring the claim is attested to by the seal.
    pub fn verify_integrity(&self) -> Result<(), VerificationError> {
        self.verify_integrity_with_context(
            &VerifierContext::default(),
            SetInclusionReceiptVerifierParameters::default(),
            Some(RecursionVerifierParameters::default()),
        )
    }
    */

    /// Verify the integrity of this receipt, ensuring the claim is attested to by the seal.
    // TODO: Use a different error type (e.g. the one from risc0-zkvm).
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
        set_verifier_params: SetInclusionReceiptVerifierParameters,
        // used when target_os = zkvm
        _recursion_verifier_params: Option<RecursionVerifierParameters>,
    ) -> Result<(), VerificationError> {
        let path_root = merkle_path_root(self.claim.digest::<sha::Impl>(), &self.merkle_path);

        // Calculate the expected value of the journal generated by the aggregation set builder.
        let expected_root_claim = ReceiptClaim::ok(
            set_verifier_params.image_id,
            GuestState {
                self_image_id: set_verifier_params.image_id,
                mmr: MerkleMountainRange::new_finalized(path_root),
            }
            .encode(),
        );

        // If provided, directly verify the provided root receipt and check its consistency against
        // the calculated root of the provided Merkle path.
        if let Some(ref root_receipt) = self.root {
            root_receipt.verify_integrity_with_context(ctx)?;
            if root_receipt.claim()?.digest::<sha::Impl>()
                != expected_root_claim.digest::<sha::Impl>()
            {
                return Err(VerificationError::ClaimDigestDoesNotMatch {
                    claim_digest: root_receipt.claim()?.digest::<sha::Impl>(),
                    expected: expected_root_claim.digest::<sha::Impl>(),
                });
            }
            return Ok(());
        }

        #[cfg(target_os = "zkvm")]
        if let Some(params) = _recursion_verifier_params {
            risc0_zkvm::guest::env::verify_assumption(
                expected_root_claim.digest::<sha::Impl>(),
                params.control_root.unwrap_or(Digest::ZERO),
            )?;
            return Ok(());
        }

        Err(VerificationError::RootNotVerified { path_root })
    }

    /// Encode the seal of the given receipt for use with EVM smart contract verifiers.
    ///
    /// Appends the verifier selector, determined from the first 4 bytes of the verifier
    /// parameters digest, which contains the aggregation set builder image ID. If non-empty, the
    /// root receipt will be appended.
    pub fn abi_encode_seal(&self) -> Result<Vec<u8>, SetInclusionEncodingError> {
        let selector = &self.verifier_parameters.as_bytes()[..4];
        let merkle_path: Vec<B256> = self
            .merkle_path
            .iter()
            .map(|x| <[u8; DIGEST_BYTES]>::from(*x).into())
            .collect();
        let root_seal: Vec<u8> = self.root.as_ref().map(encode_seal).unwrap_or(Ok(vec![]))?;
        let seal = Seal {
            path: merkle_path,
            root_seal: root_seal.into(),
        };
        let mut encoded_seal = Vec::<u8>::with_capacity(selector.len() + seal.abi_encoded_size());
        encoded_seal.extend_from_slice(selector);
        encoded_seal.extend_from_slice(&seal.abi_encode());
        Ok(encoded_seal)
    }
}

fn extract_path(seal: &[u8]) -> Result<Vec<Digest>, SetInclusionDecodingError> {
    // Early return if seal is too short to contain a path
    if seal.len() <= 4 {
        return Ok(Vec::new());
    }

    // Skip the first 4 bytes (selector) and decode the seal
    let aggregation_seal = <Seal>::abi_decode(&seal[4..])?;

    // Convert each path element to a Digest
    aggregation_seal
        .path
        .iter()
        .map(|x| Digest::try_from(x.as_slice()).map_err(|_| SetInclusionDecodingError::Digest))
        .collect()
}

pub fn decode_set_inclusion_seal(
    seal: &[u8],
    claim: ReceiptClaim,
    verifier_parameters: Digest,
) -> Result<SetInclusionReceipt<ReceiptClaim>, SetInclusionDecodingError> {
    let receipt = SetInclusionReceipt::from_path_with_verifier_params(
        claim.clone(),
        extract_path(seal)?,
        verifier_parameters,
    );

    Ok(receipt)
}

// TODO: Extract this method to a core crate to dedup with the one in risc0-ethereum-contracts
fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>, SetInclusionEncodingError> {
    match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest::<sha::Impl>().as_bytes().to_vec();
            let selector = &[0u8; 4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            Ok(selector_seal)
        }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            // Create a new vector with the capacity to hold both selector and seal
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            Ok(selector_seal)
        }
        _ => Err(SetInclusionEncodingError::UnsupportedReceipt),
    }
}

/// Verifier parameters used to verify a [SetInclusionReceipt].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetInclusionReceiptVerifierParameters {
    /// Image ID for the aggregation set builder guest.
    pub image_id: Digest,
}

impl Digestible for SetInclusionReceiptVerifierParameters {
    /// Hash the [SetInclusionReceiptVerifierParameters] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.SetInclusionReceiptVerifierParameters",
            &[self.image_id],
            &[],
        )
    }
}

/* TODO(#353)
impl Default for SetInclusionReceiptVerifierParameters {
    /// Default set of parameters used to verify a
    /// [SetInclusionReceipt][super::SetInclusionReceipt].
    fn default() -> Self {
        Self {
            image_id: SET_BUILDER_ID.into(),
        }
    }
}
*/

// TODO(victor): Move this into risc0-zkvm?
/// Verifier parameters used for recursive verification (e.g. via env::verify) of receipts.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RecursionVerifierParameters {
    /// Control root to use for verifying claims via env::verify_assumption. If not provided, the
    /// zero digest will be used, which means the same (zkVM) control root used to verify the guest
    /// execution will be used to verify this claim.
    pub control_root: Option<Digest>,
}
