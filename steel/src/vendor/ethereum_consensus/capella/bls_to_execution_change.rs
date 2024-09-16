use crate::ethereum_consensus::{
    primitives::{BlsPublicKey, BlsSignature, ExecutionAddress, ValidatorIndex},
    ssz::prelude::*,
};

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BlsToExecutionChange {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub validator_index: ValidatorIndex,
    #[serde(rename = "from_bls_pubkey")]
    pub from_bls_public_key: BlsPublicKey,
    pub to_execution_address: ExecutionAddress,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: BlsSignature,
}
