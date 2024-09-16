use crate::ethereum_consensus::{
    phase0::AttestationData,
    primitives::{BlsSignature, Epoch, ValidatorIndex},
    ssz::prelude::*,
};

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct AttesterSlashing<const MAX_VALIDATORS_PER_SLOT: usize> {
    pub attestation_1: IndexedAttestation<MAX_VALIDATORS_PER_SLOT>,
    pub attestation_2: IndexedAttestation<MAX_VALIDATORS_PER_SLOT>,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct IndexedAttestation<const MAX_VALIDATORS_PER_SLOT: usize> {
    #[serde(with = "crate::ethereum_consensus::serde::seq_of_str")]
    pub attesting_indices: List<ValidatorIndex, MAX_VALIDATORS_PER_SLOT>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct Attestation<const MAX_VALIDATORS_PER_SLOT: usize, const MAX_COMMITTEES_PER_SLOT: usize> {
    pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_SLOT>,
    pub data: AttestationData,
    pub committee_bits: Bitvector<MAX_COMMITTEES_PER_SLOT>,
    pub signature: BlsSignature,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct Consolidation {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub source_index: ValidatorIndex,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub target_index: ValidatorIndex,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub epoch: Epoch,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SignedConsolidation {
    pub message: Consolidation,
    pub signature: BlsSignature,
}
