use crate::ethereum_consensus::{
    phase0::compute_domain,
    primitives::{BlsPublicKey, BlsSignature, Domain, DomainType, ExecutionAddress},
    ssz::prelude::*,
    state_transition::Context,
    Error,
};

#[derive(Debug, Clone, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ValidatorRegistration {
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub gas_limit: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub timestamp: u64,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

#[derive(Debug, Clone, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedValidatorRegistration {
    pub message: ValidatorRegistration,
    pub signature: BlsSignature,
}

pub fn compute_builder_domain(context: &Context) -> Result<Domain, Error> {
    let domain_type = DomainType::ApplicationBuilder;
    compute_domain(domain_type, None, None, context)
}
