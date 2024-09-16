use crate::ethereum_consensus::{primitives::Bytes32, ssz::prelude::*, Error as ConsensusError};
pub use c_kzg::KzgSettings;
use thiserror::Error;

pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const BYTES_PER_G1_POINT: usize = 48;
pub const BYTES_PER_G2_POINT: usize = 96;

pub type FieldElement = Bytes32;
pub type KzgCommitment = ByteVector<BYTES_PER_COMMITMENT>;
pub type KzgProof = ByteVector<BYTES_PER_PROOF>;
pub type G1Point = KzgCommitment;
pub type G2Point = ByteVector<BYTES_PER_G2_POINT>;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TrustedSetup {
    g1_lagrange: Vec<G1Point>,
    g2_monomial: Vec<G2Point>,
}

impl TrustedSetup {
    pub fn to_g1_bytes(&self) -> Vec<[u8; BYTES_PER_G1_POINT]> {
        self.g1_lagrange
            .iter()
            .map(|point| point.as_ref().try_into().expect("right size"))
            .collect()
    }

    pub fn to_g2_bytes(&self) -> Vec<[u8; BYTES_PER_G2_POINT]> {
        self.g2_monomial
            .iter()
            .map(|point| point.as_ref().try_into().expect("right size"))
            .collect()
    }
}

pub fn kzg_settings_from_json(trusted_setup_json: &str) -> Result<KzgSettings, ConsensusError> {
    let trusted_setup: TrustedSetup = serde_json::from_str(trusted_setup_json)?;

    KzgSettings::load_trusted_setup(&trusted_setup.to_g1_bytes(), &trusted_setup.to_g2_bytes())
        .map_err(|err| ConsensusError::from(Error::from(err)))
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    CKzg(#[from] c_kzg::Error),
    #[error("proof verification failed")]
    InvalidProof,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProofAndEvaluation {
    pub proof: KzgProof,
    pub evaluation: FieldElement,
}

pub fn blob_to_kzg_commitment<Blob: AsRef<[u8]>>(
    blob: Blob,
    kzg_settings: &KzgSettings,
) -> Result<KzgCommitment, Error> {
    let blob = c_kzg::Blob::from_bytes(blob.as_ref())?;

    let commitment = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, kzg_settings)?;
    let inner = KzgCommitment::try_from(commitment.to_bytes().as_slice()).expect("correct size");
    Ok(inner)
}

pub fn compute_kzg_proof<Blob: AsRef<[u8]>>(
    blob: Blob,
    evaluation_point: &FieldElement,
    kzg_settings: &KzgSettings,
) -> Result<ProofAndEvaluation, Error> {
    let blob = c_kzg::Blob::from_bytes(blob.as_ref())?;
    let evaluation_point = c_kzg::Bytes32::from_bytes(evaluation_point.as_ref())?;

    let (proof, evaluation) =
        c_kzg::KzgProof::compute_kzg_proof(&blob, &evaluation_point, kzg_settings)?;
    let proof = KzgProof::try_from(proof.to_bytes().as_slice()).expect("correct size");
    let evaluation = FieldElement::try_from(evaluation.as_slice()).expect("correct size");

    let result = ProofAndEvaluation { proof, evaluation };
    Ok(result)
}

pub fn compute_blob_kzg_proof<Blob: AsRef<[u8]>>(
    blob: Blob,
    commitment: &KzgCommitment,
    kzg_settings: &KzgSettings,
) -> Result<KzgProof, Error> {
    let blob = c_kzg::Blob::from_bytes(blob.as_ref())?;
    let commitment = c_kzg::Bytes48::from_bytes(commitment.as_ref()).expect("correct size");

    let proof = c_kzg::KzgProof::compute_blob_kzg_proof(&blob, &commitment, kzg_settings)?;

    Ok(KzgProof::try_from(proof.to_bytes().as_slice()).expect("input is correct size"))
}

pub fn verify_kzg_proof(
    commitment: &KzgCommitment,
    evaluation_point: &FieldElement,
    result_point: &FieldElement,
    proof: &KzgProof,
    kzg_settings: &KzgSettings,
) -> Result<(), Error> {
    let evaluation_point = c_kzg::Bytes32::from_bytes(evaluation_point.as_ref())?;
    let result_point = c_kzg::Bytes32::from_bytes(result_point.as_ref())?;
    let commitment = c_kzg::Bytes48::from_bytes(commitment.as_ref()).expect("correct size");
    let proof = c_kzg::Bytes48::from_bytes(proof.as_ref()).expect("correct size");

    let res = c_kzg::KzgProof::verify_kzg_proof(
        &commitment,
        &evaluation_point,
        &result_point,
        &proof,
        kzg_settings,
    )?;

    res.then_some(()).ok_or(Error::InvalidProof)
}

pub fn verify_blob_kzg_proof<Blob: AsRef<[u8]>>(
    blob: Blob,
    commitment: &KzgCommitment,
    proof: &KzgProof,
    kzg_settings: &KzgSettings,
) -> Result<(), Error> {
    let blob = c_kzg::Blob::from_bytes(blob.as_ref())?;
    let commitment = c_kzg::Bytes48::from_bytes(commitment.as_ref()).unwrap();
    let proof = c_kzg::Bytes48::from_bytes(proof.as_ref()).unwrap();

    let res = c_kzg::KzgProof::verify_blob_kzg_proof(&blob, &commitment, &proof, kzg_settings)?;

    res.then_some(()).ok_or(Error::InvalidProof)
}

pub fn verify_blob_kzg_proof_batch<Blob: AsRef<[u8]>>(
    blobs: &[Blob],
    commitments: &[KzgCommitment],
    proofs: &[KzgProof],
    kzg_settings: &KzgSettings,
) -> Result<(), Error> {
    let mut c_kzg_blobs = Vec::with_capacity(blobs.len());
    let mut c_kzg_commitments = Vec::with_capacity(commitments.len());
    let mut c_kzg_proofs = Vec::with_capacity(proofs.len());

    for blob in blobs {
        let blob = c_kzg::Blob::from_bytes(blob.as_ref())?;
        c_kzg_blobs.push(blob);
    }
    for commitment in commitments {
        let commitment = c_kzg::Bytes48::from_bytes(commitment.as_ref()).unwrap();
        c_kzg_commitments.push(commitment);
    }
    for proof in proofs {
        let proof = c_kzg::Bytes48::from_bytes(proof.as_ref()).unwrap();
        c_kzg_proofs.push(proof);
    }

    let res = c_kzg::KzgProof::verify_blob_kzg_proof_batch(
        &c_kzg_blobs,
        &c_kzg_commitments,
        &c_kzg_proofs,
        kzg_settings,
    )?;

    res.then_some(()).ok_or(Error::InvalidProof)
}
