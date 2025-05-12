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

//! Wrapper around the ethereum_consensus crate adding Electra support.

#![allow(dead_code)]

use alloy_primitives::B256;
use ssz::prelude::*;

pub use ethereum_consensus::{altair, bellatrix, capella, deneb, phase0, ssz, Fork};

pub mod electra {
    use ethereum_consensus::{
        altair::SyncAggregate,
        capella::SignedBlsToExecutionChange,
        crypto::KzgCommitment,
        phase0::{AttestationData, Deposit, Eth1Data, ProposerSlashing, SignedVoluntaryExit},
        primitives::{
            BlsPublicKey, BlsSignature, Bytes32, ExecutionAddress, Gwei, Root, Slot, ValidatorIndex,
        },
        ssz::prelude::*,
    };

    pub use ethereum_consensus::deneb::ExecutionPayload;

    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct AttesterSlashing<const MAX_VALIDATORS_PER_COMMITTEE: usize> {
        pub attestation_1: IndexedAttestation<MAX_VALIDATORS_PER_SLOT>,
        pub attestation_2: IndexedAttestation<MAX_VALIDATORS_PER_SLOT>,
    }

    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct IndexedAttestation<const MAX_VALIDATORS_PER_SLOT: usize> {
        #[serde(with = "ethereum_consensus::serde::seq_of_str")]
        pub attesting_indices: List<ValidatorIndex, MAX_VALIDATORS_PER_SLOT>,
        pub data: AttestationData,
        pub signature: BlsSignature,
    }

    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct Attestation<
        const MAX_VALIDATORS_PER_SLOT: usize,
        const MAX_COMMITTEES_PER_SLOT: usize,
    > {
        pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_SLOT>,
        pub data: AttestationData,
        pub signature: BlsSignature,
        pub committee_bits: Bitvector<MAX_COMMITTEES_PER_SLOT>,
    }

    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct DepositRequest {
        #[serde(rename = "pubkey")]
        pub public_key: BlsPublicKey,
        pub withdrawal_credentials: Bytes32,
        #[serde(with = "ethereum_consensus::serde::as_str")]
        pub amount: Gwei,
        pub signature: BlsSignature,
        #[serde(with = "ethereum_consensus::serde::as_str")]
        pub index: u64,
    }

    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct WithdrawalRequest {
        pub source_address: ExecutionAddress,
        #[serde(rename = "validator_pubkey")]
        pub validator_public_key: BlsPublicKey,
        #[serde(with = "ethereum_consensus::serde::as_str")]
        pub amount: Gwei,
    }

    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct ConsolidationRequest {
        pub source_address: ExecutionAddress,
        #[serde(rename = "source_pubkey")]
        pub source_public_key: BlsPublicKey,
        #[serde(rename = "target_pubkey")]
        pub target_public_key: BlsPublicKey,
    }

    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct ExecutionRequests<
        const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
        const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize,
    > {
        pub deposits: List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>,
        pub withdrawals: List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>,
        pub consolidations: List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>,
    }

    #[derive(
        Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct BeaconBlockBody<
        const MAX_PROPOSER_SLASHINGS: usize,
        const MAX_VALIDATORS_PER_SLOT: usize,
        const MAX_COMMITTEES_PER_SLOT: usize,
        const MAX_ATTESTER_SLASHINGS_ELECTRA: usize,
        const MAX_ATTESTATIONS_ELECTRA: usize,
        const MAX_DEPOSITS: usize,
        const MAX_VOLUNTARY_EXITS: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
        const MAX_BLS_TO_EXECUTION_CHANGES: usize,
        const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
        const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
        const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize,
    > {
        pub randao_reveal: BlsSignature,
        pub eth1_data: Eth1Data,
        pub graffiti: Bytes32,
        pub proposer_slashings: List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
        pub attester_slashings:
            List<AttesterSlashing<MAX_VALIDATORS_PER_SLOT>, MAX_ATTESTER_SLASHINGS_ELECTRA>,
        pub attestations: List<
            Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>,
            MAX_ATTESTATIONS_ELECTRA,
        >,
        pub deposits: List<Deposit, MAX_DEPOSITS>,
        pub voluntary_exits: List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
        pub sync_aggregate: SyncAggregate<SYNC_COMMITTEE_SIZE>,
        pub execution_payload: ExecutionPayload<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
        pub bls_to_execution_changes:
            List<SignedBlsToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
        pub blob_kzg_commitments: List<KzgCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
        pub execution_requests: ExecutionRequests<
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        >,
    }

    #[derive(
        Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct BeaconBlock<
        const MAX_PROPOSER_SLASHINGS: usize,
        const MAX_VALIDATORS_PER_SLOT: usize,
        const MAX_COMMITTEES_PER_SLOT: usize,
        const MAX_ATTESTER_SLASHINGS_ELECTRA: usize,
        const MAX_ATTESTATIONS_ELECTRA: usize,
        const MAX_DEPOSITS: usize,
        const MAX_VOLUNTARY_EXITS: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
        const MAX_BLS_TO_EXECUTION_CHANGES: usize,
        const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
        const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
        const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize,
    > {
        #[serde(with = "ethereum_consensus::serde::as_str")]
        pub slot: Slot,
        #[serde(with = "ethereum_consensus::serde::as_str")]
        pub proposer_index: ValidatorIndex,
        pub parent_root: Root,
        pub state_root: Root,
        pub body: BeaconBlockBody<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_SLOT,
            MAX_COMMITTEES_PER_SLOT,
            MAX_ATTESTER_SLASHINGS_ELECTRA,
            MAX_ATTESTATIONS_ELECTRA,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        >,
    }

    #[derive(
        Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct SignedBeaconBlock<
        const MAX_PROPOSER_SLASHINGS: usize,
        const MAX_VALIDATORS_PER_SLOT: usize,
        const MAX_COMMITTEES_PER_SLOT: usize,
        const MAX_ATTESTER_SLASHINGS_ELECTRA: usize,
        const MAX_ATTESTATIONS_ELECTRA: usize,
        const MAX_DEPOSITS: usize,
        const MAX_VOLUNTARY_EXITS: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
        const MAX_BLS_TO_EXECUTION_CHANGES: usize,
        const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
        const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
        const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize,
    > {
        pub message: BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_SLOT,
            MAX_COMMITTEES_PER_SLOT,
            MAX_ATTESTER_SLASHINGS_ELECTRA,
            MAX_ATTESTATIONS_ELECTRA,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        >,
        pub signature: BlsSignature,
    }

    pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
    pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;

    pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8192;
    pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;
    pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;

    pub const MAX_VALIDATORS_PER_COMMITTEE: usize =
        ethereum_consensus::phase0::mainnet::MAX_VALIDATORS_PER_COMMITTEE;
    pub const MAX_COMMITTEES_PER_SLOT: usize =
        ethereum_consensus::phase0::mainnet::MAX_COMMITTEES_PER_SLOT as usize;

    pub const MAX_VALIDATORS_PER_SLOT: usize =
        MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT;
}

pub use ethereum_consensus::types::ExecutionPayloadRef;

#[derive(Debug, Clone, PartialEq, Eq, Serializable, HashTreeRoot)]
#[ssz(transparent)]
pub enum SignedBeaconBlock<
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_BLS_TO_EXECUTION_CHANGES: usize,
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
    const MAX_VALIDATORS_PER_SLOT: usize,
    const MAX_COMMITTEES_PER_SLOT: usize,
    const MAX_ATTESTER_SLASHINGS_ELECTRA: usize,
    const MAX_ATTESTATIONS_ELECTRA: usize,
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize,
> {
    Phase0(
        phase0::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
        >,
    ),
    Altair(
        altair::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
    Bellatrix(
        bellatrix::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
        >,
    ),
    Capella(
        capella::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
        >,
    ),
    Deneb(
        deneb::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
        >,
    ),
    Electra(
        electra::SignedBeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_SLOT,
            MAX_COMMITTEES_PER_SLOT,
            MAX_ATTESTER_SLASHINGS_ELECTRA,
            MAX_ATTESTATIONS_ELECTRA,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_BLS_TO_EXECUTION_CHANGES,
            MAX_BLOB_COMMITMENTS_PER_BLOCK,
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        >,
    ),
}

impl<
        const MAX_PROPOSER_SLASHINGS: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const MAX_ATTESTER_SLASHINGS: usize,
        const MAX_ATTESTATIONS: usize,
        const MAX_DEPOSITS: usize,
        const MAX_VOLUNTARY_EXITS: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
        const MAX_BLS_TO_EXECUTION_CHANGES: usize,
        const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize,
        const MAX_VALIDATORS_PER_SLOT: usize,
        const MAX_COMMITTEES_PER_SLOT: usize,
        const MAX_ATTESTER_SLASHINGS_ELECTRA: usize,
        const MAX_ATTESTATIONS_ELECTRA: usize,
        const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
        const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize,
    >
    SignedBeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_VALIDATORS_PER_SLOT,
        MAX_COMMITTEES_PER_SLOT,
        MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_ATTESTATIONS_ELECTRA,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >
{
    /// Returns the fork version of the block.
    pub fn version(&self) -> Fork {
        match self {
            Self::Phase0(_) => Fork::Phase0,
            Self::Altair(_) => Fork::Altair,
            Self::Bellatrix(_) => Fork::Bellatrix,
            Self::Capella(_) => Fork::Capella,
            Self::Deneb(_) => Fork::Deneb,
            Self::Electra(_) => Fork::Electra,
        }
    }

    /// Returns the beacon block root.
    pub fn root(&self) -> Result<B256, MerkleizationError> {
        let root = match self {
            Self::Phase0(inner) => inner.message.hash_tree_root()?,
            Self::Altair(inner) => inner.message.hash_tree_root()?,
            Self::Bellatrix(inner) => inner.message.hash_tree_root()?,
            Self::Capella(inner) => inner.message.hash_tree_root()?,
            Self::Deneb(inner) => inner.message.hash_tree_root()?,
            Self::Electra(inner) => inner.message.hash_tree_root()?,
        };
        Ok(root.0.into())
    }

    pub fn execution_payload(
        &self,
    ) -> Option<
        ExecutionPayloadRef<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        >,
    > {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(_) => None,
            Self::Bellatrix(inner) => Some(From::from(&inner.message.body.execution_payload)),
            Self::Capella(inner) => Some(From::from(&inner.message.body.execution_payload)),
            Self::Deneb(inner) => Some(From::from(&inner.message.body.execution_payload)),
            Self::Electra(inner) => Some(From::from(&inner.message.body.execution_payload)),
        }
    }
}

pub mod mainnet {
    use super::electra::{
        MAX_ATTESTATIONS_ELECTRA, MAX_ATTESTER_SLASHINGS_ELECTRA, MAX_COMMITTEES_PER_SLOT,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_VALIDATORS_PER_SLOT, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
    };
    use ethereum_consensus::{
        altair::mainnet::SYNC_COMMITTEE_SIZE,
        bellatrix::mainnet::{
            BYTES_PER_LOGS_BLOOM, MAX_BYTES_PER_TRANSACTION, MAX_EXTRA_DATA_BYTES,
            MAX_TRANSACTIONS_PER_PAYLOAD,
        },
        capella::mainnet::{MAX_BLS_TO_EXECUTION_CHANGES, MAX_WITHDRAWALS_PER_PAYLOAD},
        deneb::mainnet::MAX_BLOB_COMMITMENTS_PER_BLOCK,
        phase0::mainnet::{
            MAX_ATTESTATIONS, MAX_ATTESTER_SLASHINGS, MAX_DEPOSITS, MAX_PROPOSER_SLASHINGS,
            MAX_VALIDATORS_PER_COMMITTEE, MAX_VOLUNTARY_EXITS,
        },
    };

    pub type SignedBeaconBlock = super::SignedBeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        MAX_VALIDATORS_PER_SLOT,
        MAX_COMMITTEES_PER_SLOT,
        MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_ATTESTATIONS_ELECTRA,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    >;
}
