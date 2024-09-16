use crate::ethereum_consensus::{
    bellatrix::Transaction,
    capella::Withdrawal,
    electra::beacon_state::{DepositReceipt, ExecutionLayerWithdrawalRequest},
    primitives::{Bytes32, ExecutionAddress, Hash32, Root},
    ssz::prelude::*,
    Error,
};

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionPayload<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const MAX_BYTES_PER_TRANSACTION: usize,
    const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
    const MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD: usize,
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
> {
    pub parent_hash: Hash32,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: Bytes32,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub block_number: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub gas_limit: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub gas_used: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub timestamp: u64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub base_fee_per_gas: U256,
    pub block_hash: Hash32,
    pub transactions: List<Transaction<MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
    pub withdrawals: List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub blob_gas_used: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub excess_blob_gas: u64,
    pub deposit_receipts: List<DepositReceipt, MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD>,
    pub withdrawal_requests:
        List<ExecutionLayerWithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>,
}

#[derive(
    Default, Debug, Clone, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct ExecutionPayloadHeader<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    pub parent_hash: Hash32,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: Bytes32,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub block_number: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub gas_limit: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub gas_used: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub timestamp: u64,
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub base_fee_per_gas: U256,
    pub block_hash: Hash32,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub blob_gas_used: u64,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub excess_blob_gas: u64,
    pub deposit_receipts_root: Root,
    pub withdrawal_requests_root: Root,
}

impl<
        'a,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const MAX_BYTES_PER_TRANSACTION: usize,
        const MAX_TRANSACTIONS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWALS_PER_PAYLOAD: usize,
        const MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD: usize,
        const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize,
    >
    TryFrom<
        &'a ExecutionPayload<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        >,
    > for ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    type Error = Error;

    fn try_from(
        payload: &'a ExecutionPayload<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            MAX_BYTES_PER_TRANSACTION,
            MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
            MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        >,
    ) -> Result<ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>, Self::Error>
    {
        let transactions_root = payload.transactions.hash_tree_root()?;
        let withdrawals_root = payload.withdrawals.hash_tree_root()?;
        let deposit_receipts_root = payload.deposit_receipts.hash_tree_root()?;
        let withdrawal_requests_root = payload.withdrawal_requests.hash_tree_root()?;

        Ok(ExecutionPayloadHeader {
            parent_hash: payload.parent_hash.clone(),
            fee_recipient: payload.fee_recipient.clone(),
            state_root: payload.state_root.clone(),
            receipts_root: payload.receipts_root.clone(),
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao.clone(),
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash.clone(),
            transactions_root,
            withdrawals_root,
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            deposit_receipts_root,
            withdrawal_requests_root,
        })
    }
}
