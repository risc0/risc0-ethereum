// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

extern crate alloc;

use alloc::vec::Vec;
use core::{borrow::Borrow, fmt::Debug};

use alloy_primitives::{Keccak256, B256};
use alloy_sol_types::SolValue;
use risc0_binfmt::{tagged_struct, Digestible};
use risc0_zkvm::{
    sha,
    sha::{Digest, Sha256, DIGEST_BYTES},
    InnerReceipt, MaybePruned, Receipt, ReceiptClaim, VerifierContext,
};
use serde::{Deserialize, Serialize};

alloy_sol_types::sol! {
    /// Seal of the SetInclusionReceipt.
    #[sol(all_derives)]
    struct Seal {
        /// Merkle path to the leaf.
        bytes32[] path;
        /// Root seal.
        bytes root_seal;
    }
}

/// A receipt for a claim that is part of a set of verified claims (i.e. an aggregation).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SetInclusionReceipt<Claim>
where
    Claim: Digestible + Debug + Clone + Serialize,
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
    /// Acts as a fingerprint to identity differing proof system or circuit versions between a
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
    #[error("failed to confirm the validity the set root: {path_root}")]
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
pub enum EncodingError {
    #[error("unsupported receipt type")]
    UnsupportedReceiptType,
}

impl<Claim> SetInclusionReceipt<Claim>
where
    Claim: Digestible + Debug + Clone + Serialize,
{
    /// Construct a [SetInclusionReceipt] with the given Merkle inclusion path and claim.
    ///
    /// Path should contain all sibling nodes in the tree from the leaf to the root. Note that the
    /// path does not include the leaf or the root itself. Resulting receipt will have default
    /// verifier paramaters and no root receipt.
    #[cfg(feature = "verify")]
    pub fn from_path(claim: impl Into<MaybePruned<Claim>>, merkle_path: Vec<Digest>) -> Self {
        Self {
            claim: claim.into(),
            root: None,
            merkle_path,
            verifier_parameters: SetInclusionReceiptVerifierParameters::default()
                .digest::<sha::Impl>(),
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

    /// Verify the integrity of this receipt, ensuring the claim is attested to by the seal.
    #[cfg(feature = "verify")]
    pub fn verify_integrity(&self) -> Result<(), VerificationError> {
        self.verify_integrity_with_context(
            &VerifierContext::default(),
            SetInclusionReceiptVerifierParameters::default(),
            Some(RecursionVerifierParamters::default()),
        )
    }

    /// Verify the integrity of this receipt, ensuring the claim is attested to by the seal.
    // TODO: Use a different error type (e.g. the one from risc0-zkvm).
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
        set_verifier_params: SetInclusionReceiptVerifierParameters,
        recursion_verifier_params: Option<RecursionVerifierParamters>,
    ) -> Result<(), VerificationError> {
        let path_root = merkle_path_root(&self.claim.digest::<sha::Impl>(), &self.merkle_path);

        // Calculate the expected value of the journal generated by the aggregation set builder.
        let expected_root_claim = ReceiptClaim::ok(
            set_verifier_params.image_id,
            GuestOutput::new(set_verifier_params.image_id, path_root).abi_encode(),
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

        if cfg!(target_os = "zkvm") && recursion_verifier_params.is_some() {
            risc0_zkvm::guest::env::verify_assumption(
                expected_root_claim.digest::<sha::Impl>(),
                recursion_verifier_params
                    .map(|params| params.control_root)
                    .flatten()
                    .unwrap_or(Digest::ZERO),
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
    pub fn abi_encode_seal(&self) -> Result<Vec<u8>, EncodingError> {
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

// TODO: Extract this method to a core crate to dedup with the one in risc0-ethereum-contracts
fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>, EncodingError> {
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
        _ => Err(EncodingError::UnsupportedReceiptType),
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

#[cfg(feature = "verify")]
mod verify {
    use super::SetInclusionReceiptVerifierParameters;
    pub use guest_set_builder::{SET_BUILDER_ELF, SET_BUILDER_ID, SET_BUILDER_PATH};

    impl Default for SetInclusionReceiptVerifierParameters {
        /// Default set of parameters used to verify a
        /// [SetInclusionReceipt][super::SetInclusionReceipt].
        fn default() -> Self {
            Self {
                image_id: SET_BUILDER_ID.into(),
            }
        }
    }
}

#[cfg(feature = "verify")]
pub use verify::*;

// TODO(victor): Move this into risc0-zkvm?
/// Verifier parameters used for recursive verification (e.g. via env::verify) of receipts.
#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RecursionVerifierParamters {
    /// Control root to use for verifying claims via env::verify_assumption. If not provided, the
    /// zero digest will be used, which means the same (zkVM) control root used to verify the guest
    /// execution will be used to verify this claim.
    pub control_root: Option<Digest>,
}

/// Input of the aggregation set builder guest.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum GuestInput {
    /// Input is a leaf of the Merkle tree.
    Singleton {
        self_image_id: Digest,
        claim: ReceiptClaim,
    },
    /// Input is an inner node of the Merkle tree.
    Join {
        self_image_id: Digest,
        left_set_root: Digest,
        right_set_root: Digest,
    },
}

impl GuestInput {
    #[inline]
    pub fn image_id(&self) -> Digest {
        match self {
            GuestInput::Singleton { self_image_id, .. } => *self_image_id,
            GuestInput::Join { self_image_id, .. } => *self_image_id,
        }
    }

    #[inline]
    pub fn root(&self) -> Digest {
        match self {
            GuestInput::Singleton { claim, .. } => claim.digest::<sha::Impl>(),
            GuestInput::Join {
                left_set_root,
                right_set_root,
                ..
            } => commutative_keccak256(left_set_root, right_set_root),
        }
    }

    /// Creates a [GuestOutput] from the input.
    #[inline]
    pub fn to_output(&self) -> GuestOutput {
        GuestOutput::new(self.image_id(), self.root())
    }
}

/// Calculate the Merkle root for a tree with the given list of digests as leaves.
///
/// Panics if the given list of leaves is empty.
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    match leaves {
        [] => panic!("digest list is empty, cannot compute Merkle root"),
        [digest] => *digest, // If only one digest, return it as the root
        _ => {
            // Split the list into two halves
            let (left, right) = leaves.split_at(leaves.len().next_power_of_two() / 2);
            let left_root = merkle_root(left);
            let right_root = merkle_root(right);
            // Hash the combined roots of the left and right halves
            commutative_keccak256(&left_root, &right_root)
        }
    }
}

// TODO(victor) Should this be assembled into under a struct and impl rather than as discrete
// functions?
/// Calculate the Merkle path proving inclusion of the leaf at the given index in a tree
/// constructed from the given leaves. The leaf and root are not included.
///
/// Panics if the given index is out of bounds.
pub fn merkle_path(leaves: &[Digest], index: usize) -> Vec<Digest> {
    // Ensure that the index is valid.
    leaves.get(index).unwrap_or_else(|| {
        panic!(
            "no leaf with index {index} in tree of size {}",
            leaves.len()
        )
    });

    match leaves {
        [] => unreachable!(),
        [_] => Vec::new(), // If only one digest, return an empty path.
        _ => {
            // Take the most-significant bit to determine whether the leaf is in the left or the
            // right subtree, and determine the index in that subtree.
            let index_bitsize = leaves.len().next_power_of_two().ilog2() as usize;
            debug_assert!(index_bitsize >= 1);
            let msb_mask = 1 << (index_bitsize - 1);
            let is_left = index & msb_mask == 0;
            let subindex = index & (msb_mask - 1);

            // Split the list into two halves
            let (left, right) = leaves.split_at(leaves.len().next_power_of_two() / 2);
            let (ancestor, sibling) = match is_left {
                true => (left, right),
                false => (right, left),
            };
            let sibling_root = merkle_root(sibling);
            let mut path = merkle_path(ancestor, subindex);
            path.push(sibling_root);
            path
        }
    }
}

/// Calculate the root of the path assuming the given leaf value.
///
/// NOTE: The result of this function must be checked to be the root of some committed Merkle tree.
pub fn merkle_path_root(
    leaf: &Digest,
    path: impl IntoIterator<Item = impl Borrow<Digest>>,
) -> Digest {
    path.into_iter()
        .fold(*leaf, |a, b| commutative_keccak256(a.borrow(), b.borrow()))
}

/// Computes the hash of a sorted pair of [Digest].
fn commutative_keccak256(a: &Digest, b: &Digest) -> Digest {
    let mut hasher = Keccak256::new();
    if a.as_bytes() < b.as_bytes() {
        hasher.update(a.as_bytes());
        hasher.update(b.as_bytes());
    } else {
        hasher.update(b.as_bytes());
        hasher.update(a.as_bytes());
    }
    hasher.finalize().0.into()
}

alloy_sol_types::sol! {
    /// Journal output of aggregation set builder guest.
    #[sol(all_derives)]
    struct GuestOutput {
        /// Image ID used to verify the assumptions.
        bytes32 id;
        /// Root of the current sub-set.
        bytes32 root;
    }
}

impl GuestOutput {
    // NOTE: We use `impl Into<Digest>` here for the image ID type to accept the image ID constants
    // produced by risc0-build, which are [u8; 32].
    pub fn new(image_id: impl Into<Digest>, root: Digest) -> Self {
        Self {
            id: to_b256(image_id.into()),
            root: to_b256(root),
        }
    }

    /// ABI-encodes the output.
    #[inline]
    pub fn abi_encode(&self) -> Vec<u8> {
        SolValue::abi_encode(self)
    }

    #[inline]
    pub fn image_id(&self) -> Digest {
        self.id.0.into()
    }
    #[inline]
    pub fn root(&self) -> Digest {
        self.root.0.into()
    }
}

fn to_b256(digest: Digest) -> B256 {
    <[u8; 32]>::from(digest).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    fn assert_merkle_root(digests: &[Digest], expected_root: Digest) {
        let root = merkle_root(digests);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_root_manual() {
        let digests = vec![
            Digest::from_hex("6a428060b5d51f04583182f2ff1b565f9db661da12ee7bdc003e9ab6d5d91ba9")
                .unwrap(),
            Digest::from_hex("6a428060b5d51f04583182f2ff1b565f9db661da12ee7bdc003e9ab6d5d91ba9")
                .unwrap(),
            Digest::from_hex("6a428060b5d51f04583182f2ff1b565f9db661da12ee7bdc003e9ab6d5d91ba9")
                .unwrap(),
        ];

        assert_merkle_root(
            &digests,
            Digest::from_hex("e004c72e4cb697fa97669508df099edbc053309343772a25e56412fc7db8ebef")
                .unwrap(),
        );
    }

    #[test]
    fn test_merkle_root() {
        let digests = vec![Digest::from([0u8; 32])];
        assert_merkle_root(&digests, digests[0]);

        let digests = vec![
            Digest::from([0u8; 32]),
            Digest::from([1u8; 32]),
            Digest::from([2u8; 32]),
        ];
        assert_merkle_root(
            &digests,
            commutative_keccak256(
                &commutative_keccak256(&digests[0], &digests[1]),
                &digests[2],
            ),
        );

        let digests = vec![
            Digest::from([0u8; 32]),
            Digest::from([1u8; 32]),
            Digest::from([2u8; 32]),
            Digest::from([3u8; 32]),
        ];
        assert_merkle_root(
            &digests,
            commutative_keccak256(
                &commutative_keccak256(&digests[0], &digests[1]),
                &commutative_keccak256(&digests[2], &digests[3]),
            ),
        );
    }

    #[test]
    fn test_consistency() {
        for length in 1..=256 {
            let digests: Vec<Digest> = (0..length)
                .map(|_| rand::random::<[u8; 32]>().into())
                .collect();
            let root = merkle_root(&digests);

            for i in 0..length {
                let path = merkle_path(&digests, i);
                assert_eq!(merkle_path_root(&digests[i], &path), root);
            }
        }
    }
}
