use crate::ethereum_consensus::{
    phase0::operations::Attestation,
    primitives::{BlsPublicKey, BlsSignature, Bytes32, Epoch, Gwei, Root, ValidatorIndex},
    ssz::prelude::*,
};

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct Validator {
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
    pub withdrawal_credentials: Bytes32,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub effective_balance: Gwei,
    pub slashed: bool,
    // Status epochs
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub activation_eligibility_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub activation_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub exit_epoch: Epoch,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub withdrawable_epoch: Epoch,
}

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Serialize, serde::Deserialize)]
pub struct Eth1Block {
    pub timestamp: u64,
    pub deposit_root: Root,
    pub deposit_count: u64,
}

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation<MAX_VALIDATORS_PER_COMMITTEE>,
    pub selection_proof: BlsSignature,
}

#[derive(Default, Debug, SimpleSerialize, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedAggregateAndProof<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
    pub message: AggregateAndProof<MAX_VALIDATORS_PER_COMMITTEE>,
    pub signature: BlsSignature,
}
