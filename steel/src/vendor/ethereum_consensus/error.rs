use crate::ethereum_consensus::{
    capella::Withdrawal,
    crypto::{BlsError, KzgError},
    phase0::{AttestationData, BeaconBlockHeader, Checkpoint},
    primitives::{
        BlsPublicKey, BlsSignature, Bytes32, Epoch, ExecutionAddress, Hash32, Root, Slot,
        ValidatorIndex,
    },
    ssz::prelude::*,
    Fork,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Merkleization(#[from] MerkleizationError),
    #[error("{0}")]
    SimpleSerialize(#[from] SimpleSerializeError),
    #[error("{0}")]
    Bls(#[from] BlsError),
    #[error("{0}")]
    Kzg(#[from] KzgError),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("requested element {requested} but collection only has {bound} elements")]
    OutOfBounds { requested: usize, bound: usize },
    #[error("collection cannot be empty")]
    CollectionCannotBeEmpty,
    #[error("given index {index} is greater than the total amount of indices {total}")]
    InvalidShufflingIndex { index: usize, total: usize },
    #[error("slot {requested} is outside of allowed range ({lower_bound}, {upper_bound})")]
    SlotOutOfRange {
        requested: Slot,
        lower_bound: Slot,
        upper_bound: Slot,
    },
    #[error("overflow")]
    Overflow,
    #[error("underflow")]
    Underflow,
    #[error("{0}")]
    InvalidBlock(#[from] Box<InvalidBlock>),
    #[error("an invalid transition to a past slot {requested} from slot {current}")]
    TransitionToPreviousSlot { current: Slot, requested: Slot },
    #[error("invalid state root")]
    InvalidStateRoot,
    #[error(
    "the requested epoch {requested} is not in the required current epoch {current} or previous epoch {previous}"
    )]
    InvalidEpoch {
        requested: Epoch,
        previous: Epoch,
        current: Epoch,
    },
    #[error(
        "transition requested from a later fork {source_fork:?} to an earlier fork {destination_fork:?}"
    )]
    InvalidForkTransition {
        source_fork: Fork,
        destination_fork: Fork,
    },
    #[error("genesis time unknown for network {0}")]
    UnknownGenesisTime(String),

    #[error("an unknown preset {0} was supplied when constructing context")]
    UnknownPreset(String),
    #[error(transparent)]
    ExecutionEngine(#[from] ExecutionEngineError),
}

#[derive(Debug, Error)]
pub enum InvalidBlock {
    #[error("invalid beacon block header: {0}")]
    Header(#[from] InvalidBeaconBlockHeader),
    #[error("invalid operation: {0}")]
    InvalidOperation(#[from] InvalidOperation),
}

#[derive(Debug, Error)]
pub enum InvalidOperation {
    #[error("invalid attestation: {0}")]
    Attestation(#[from] InvalidAttestation),
    #[error("invalid indexed attestation: {0}")]
    IndexedAttestation(#[from] InvalidIndexedAttestation),
    #[error("invalid deposit: {0}")]
    Deposit(#[from] InvalidDeposit),
    #[error("invalid randao (Bls signature): {0:?}")]
    Randao(BlsSignature),
    #[error("invalid proposer slashing: {0}")]
    ProposerSlashing(#[from] InvalidProposerSlashing),
    #[error("invalid attester slashing: {0}")]
    AttesterSlashing(#[from] InvalidAttesterSlashing),
    #[error("invalid voluntary exit: {0}")]
    VoluntaryExit(#[from] InvalidVoluntaryExit),
    #[error("invalid sync aggregate: {0}")]
    SyncAggregate(#[from] InvalidSyncAggregate),
    #[error("invalid execution payload: {0}")]
    ExecutionPayload(#[from] InvalidExecutionPayload),
    #[error("invalid withdrawals: {0}")]
    Withdrawal(#[from] InvalidWithdrawals),
    #[error("invalid BLS signature to execution change: {0}")]
    BlsToExecutionChange(#[from] InvalidBlsToExecutionChange),
    #[error("invalid consolidation: {0}")]
    InvalidConsolidation(InvalidConsolidation),
}

#[derive(Debug, Error)]
pub enum InvalidBeaconBlockHeader {
    #[error("mismatch between state slot {state_slot} and block slot {block_slot}")]
    StateSlotMismatch { state_slot: Slot, block_slot: Slot },
    #[error("mismatch between the block's parent root {expected:?} and the expected parent root {provided:?}")]
    ParentBlockRootMismatch { expected: Root, provided: Root },
    #[error("proposer with index {0} is slashed")]
    ProposerSlashed(ValidatorIndex),
    #[error("block slot {block_slot} is older than the latest block header slot {latest_block_header_slot}")]
    OlderThanLatestBlockHeader {
        block_slot: Slot,
        latest_block_header_slot: Slot,
    },
    #[error("mismatch between the block proposer index {block_proposer_index} and the state proposer index {proposer_index}")]
    ProposerIndexMismatch {
        block_proposer_index: ValidatorIndex,
        proposer_index: ValidatorIndex,
    },
}

#[derive(Debug, Error)]
pub enum InvalidAttestation {
    #[error("expected length of {expected_length} in bitfield but had length {length}")]
    Bitfield {
        expected_length: usize,
        length: usize,
    },
    #[error("invalid target epoch {target}, not current ({current}) or previous epochs")]
    InvalidTargetEpoch { target: Epoch, current: Epoch },
    #[error("invalid slot {slot} (in epoch {epoch}) based on target epoch {target}")]
    InvalidSlot {
        slot: Slot,
        epoch: Epoch,
        target: Epoch,
    },
    #[error("attestation at slot {attestation_slot} is not timely for state slot {state_slot}, outside of range [{lower_bound}, {upper_bound}]")]
    NotTimely {
        state_slot: Slot,
        attestation_slot: Slot,
        lower_bound: Slot,
        upper_bound: Slot,
    },
    #[error("attestation's index {index} exceeds the current committee count {upper_bound}")]
    InvalidIndex { index: usize, upper_bound: usize },
    #[error("attestation's source checkpoint {source_checkpoint:?} does not match the expected checkpoint {expected:?} (in epoch {current})")]
    InvalidSource {
        expected: Checkpoint,
        source_checkpoint: Checkpoint,
        current: Epoch,
    },
    #[error("attestation in slot {attestation_slot} does not have the minimum delay {required_delay} against state {state_slot}")]
    NoDelay {
        attestation_slot: Slot,
        state_slot: Slot,
        required_delay: Slot,
    },
}

#[derive(Debug, Error)]
pub enum InvalidIndexedAttestation {
    #[error("attesting indices are empty")]
    AttestingIndicesEmpty,
    #[error("attesting indices are duplicated")]
    DuplicateIndices(Vec<ValidatorIndex>),
    #[error("attesting indices are not sorted")]
    AttestingIndicesNotSorted,
    #[error("index in attesting set is invalid for this state")]
    InvalidIndex(ValidatorIndex),
}

#[derive(Debug, Error)]
pub enum InvalidDeposit {
    #[error("expected {expected} deposits but only had {count} deposits")]
    IncorrectCount { expected: usize, count: usize },
    #[error("merkle validation failed for tree with depth {depth} and root {root:?} at index {index} for leaf {leaf:?} and branch {branch:?}")]
    InvalidProof {
        leaf: Node,
        branch: Vec<Node>,
        depth: usize,
        index: usize,
        root: Root,
    },
    #[error("invalid signature for deposit: {0:?}")]
    InvalidSignature(BlsSignature),
}

#[derive(Debug, Error)]
pub enum InvalidProposerSlashing {
    #[error("different slots: {0} vs. {1}")]
    SlotMismatch(Slot, Slot),
    #[error("different proposers: {0} vs. {1}")]
    ProposerMismatch(ValidatorIndex, ValidatorIndex),
    #[error("headers are equal: {0:?}")]
    HeadersAreEqual(BeaconBlockHeader),
    #[error("proposer with index {0} is not slashable")]
    ProposerIsNotSlashable(ValidatorIndex),
    #[error("header has invalid signature: {0:?}")]
    InvalidSignature(BlsSignature),
    #[error("proposer with index {0} is not in state")]
    InvalidIndex(ValidatorIndex),
}

#[derive(Debug, Error)]
pub enum InvalidAttesterSlashing {
    #[error("attestation data is not slashable: {0:?} vs. {1:?}")]
    NotSlashable(Box<AttestationData>, Box<AttestationData>),
    #[error("no validator was slashed across indices: {0:?}")]
    NoSlashings(Vec<ValidatorIndex>),
}

#[derive(Debug, Error)]
pub enum InvalidVoluntaryExit {
    #[error("validator with index {0} is not in state")]
    InvalidIndex(ValidatorIndex),
    #[error("validator is not active in the current epoch {0}")]
    InactiveValidator(Epoch),
    #[error("validator {index} already exited in {epoch}")]
    ValidatorAlreadyExited { index: ValidatorIndex, epoch: Epoch },
    #[error("exit in epoch {exit_epoch} is not eligible for processing in current epoch {current_epoch}")]
    EarlyExit {
        current_epoch: Epoch,
        exit_epoch: Epoch,
    },
    #[error("validator needs to be active for a minimum period of time (from epoch {minimum_time_active}, currently in {current_epoch})")]
    ValidatorIsNotActiveForLongEnough {
        current_epoch: Epoch,
        minimum_time_active: Epoch,
    },
    #[error("voluntary exit has invalid signature: {0:?}")]
    InvalidSignature(BlsSignature),
    #[error("validator has non-zero pending balance to withdraw in queue")]
    NonZeroPendingBalanceToWithdraw,
}

#[derive(Debug, Error)]
pub enum InvalidWithdrawals {
    #[error("expected withdrawals {expected:#?} do not match provided withdrawals {provided:#?}")]
    IncorrectWithdrawals {
        provided: Vec<Withdrawal>,
        expected: Vec<Withdrawal>,
    },
}

#[derive(Debug, Error)]
pub enum InvalidBlsToExecutionChange {
    #[error("validator index {0} is out of bounds")]
    ValidatorIndexOutOfBounds(usize),
    #[error("invalid withdrawal credentials prefix: {0}")]
    WithdrawalCredentialsPrefix(u8),
    #[error("operation's public key did not match the registered key: {0:?}")]
    PublicKeyMismatch(BlsPublicKey),
}

#[derive(Debug, Error)]
pub enum InvalidConsolidation {
    #[error("validator with index {0} is not in state")]
    InvalidIndex(ValidatorIndex),
    #[error("pending consolidations queue full")]
    PendingConsolidationsQueueFull,
    #[error("insufficient consolidation churn limit")]
    InsufficientConsolidationChurnLimit,
    #[error("source validator index equals target validator index {0}")]
    EqualSourceAndTargetIndices(ValidatorIndex),
    #[error("validator {0} is not active in the current epoch {1}")]
    InactiveValidator(ValidatorIndex, Epoch),
    #[error("exit already initiated for validator {0}")]
    ExitInitiatedForValidator(ValidatorIndex),
    #[error("consolidation in epoch {consolidation_epoch} is not eligible for processing in current epoch {current_epoch}")]
    EarlyConsolidation {
        current_epoch: Epoch,
        consolidation_epoch: Epoch,
    },
    #[error("validator {0} missing execution layer withdrawal credentials")]
    MissingExecutionWithdrawalCredentials(ValidatorIndex),
    #[error("source withdrawal credentials {source_address} do not equal target withdrawal credentials {target_address}")]
    WithdrawalCredentialsMismatch {
        source_address: ExecutionAddress,
        target_address: ExecutionAddress,
    },
}

#[derive(Debug, Error)]
pub enum InvalidSyncAggregate {
    #[error("invalid sync committee aggregate signature {signature} signing over previous slot block root {root}")]
    InvalidSignature { signature: BlsSignature, root: Root },
}

#[derive(Debug, Error)]
pub enum InvalidExecutionPayload {
    #[error("expected parent hash {expected} but block has parent hash {provided}")]
    InvalidParentHash { provided: Hash32, expected: Hash32 },
    #[error("expected randao value {expected} but block has randao value {provided}")]
    InvalidPrevRandao {
        provided: Bytes32,
        expected: Bytes32,
    },
    #[error("expected timestamp {expected} but block has timestamp {provided}")]
    InvalidTimestamp { provided: u64, expected: u64 },
    #[error("expected up to {limit} blob commmitments but block has {provided}")]
    InvalidBlobCommitments { provided: usize, limit: usize },
}

pub(crate) fn invalid_header_error(error: InvalidBeaconBlockHeader) -> Error {
    Error::InvalidBlock(Box::new(InvalidBlock::Header(error)))
}

pub(crate) fn invalid_operation_error(error: InvalidOperation) -> Error {
    Error::InvalidBlock(Box::new(InvalidBlock::InvalidOperation(error)))
}

#[derive(Debug, Error)]
pub enum ExecutionEngineError {
    #[error("invalid block hash")]
    InvalidBlockHash,
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid versioned hashes in payload")]
    InvalidVersionedHashes,
}
