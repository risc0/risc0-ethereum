//! WARNING: This file was derived by the `spec-gen` utility. DO NOT EDIT MANUALLY.
use crate::ethereum_consensus::{
    bellatrix::execution_payload as bellatrix,
    capella::execution_payload as capella,
    deneb::execution_payload as deneb,
    primitives::{Bytes32, ExecutionAddress, Hash32, Root},
    ssz::prelude::*,
    Fork as Version,
};
#[derive(Debug, Clone, PartialEq, Eq, Serializable, HashTreeRoot, serde::Serialize)]
#[ssz(transparent)]
#[serde(untagged)]
pub enum ExecutionPayloadHeader<
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    Bellatrix(bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
    Capella(capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
    Deneb(deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
}
impl<const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    pub fn bellatrix(
        &self,
    ) -> Option<&bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn bellatrix_mut(
        &mut self,
    ) -> Option<&mut bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella(
        &self,
    ) -> Option<&capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella_mut(
        &mut self,
    ) -> Option<&mut capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb(
        &self,
    ) -> Option<&deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb_mut(
        &mut self,
    ) -> Option<&mut deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn version(&self) -> Version {
        match self {
            Self::Bellatrix(_) => Version::Bellatrix,
            Self::Capella(_) => Version::Capella,
            Self::Deneb(_) => Version::Deneb,
        }
    }
    pub fn parent_hash(&self) -> &Hash32 {
        match self {
            Self::Bellatrix(inner) => &inner.parent_hash,
            Self::Capella(inner) => &inner.parent_hash,
            Self::Deneb(inner) => &inner.parent_hash,
        }
    }
    pub fn parent_hash_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.parent_hash,
            Self::Capella(inner) => &mut inner.parent_hash,
            Self::Deneb(inner) => &mut inner.parent_hash,
        }
    }
    pub fn fee_recipient(&self) -> &ExecutionAddress {
        match self {
            Self::Bellatrix(inner) => &inner.fee_recipient,
            Self::Capella(inner) => &inner.fee_recipient,
            Self::Deneb(inner) => &inner.fee_recipient,
        }
    }
    pub fn fee_recipient_mut(&mut self) -> &mut ExecutionAddress {
        match self {
            Self::Bellatrix(inner) => &mut inner.fee_recipient,
            Self::Capella(inner) => &mut inner.fee_recipient,
            Self::Deneb(inner) => &mut inner.fee_recipient,
        }
    }
    pub fn state_root(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.state_root,
            Self::Capella(inner) => &inner.state_root,
            Self::Deneb(inner) => &inner.state_root,
        }
    }
    pub fn state_root_mut(&mut self) -> &mut Bytes32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.state_root,
            Self::Capella(inner) => &mut inner.state_root,
            Self::Deneb(inner) => &mut inner.state_root,
        }
    }
    pub fn receipts_root(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.receipts_root,
            Self::Capella(inner) => &inner.receipts_root,
            Self::Deneb(inner) => &inner.receipts_root,
        }
    }
    pub fn receipts_root_mut(&mut self) -> &mut Bytes32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.receipts_root,
            Self::Capella(inner) => &mut inner.receipts_root,
            Self::Deneb(inner) => &mut inner.receipts_root,
        }
    }
    pub fn logs_bloom(&self) -> &ByteVector<BYTES_PER_LOGS_BLOOM> {
        match self {
            Self::Bellatrix(inner) => &inner.logs_bloom,
            Self::Capella(inner) => &inner.logs_bloom,
            Self::Deneb(inner) => &inner.logs_bloom,
        }
    }
    pub fn logs_bloom_mut(&mut self) -> &mut ByteVector<BYTES_PER_LOGS_BLOOM> {
        match self {
            Self::Bellatrix(inner) => &mut inner.logs_bloom,
            Self::Capella(inner) => &mut inner.logs_bloom,
            Self::Deneb(inner) => &mut inner.logs_bloom,
        }
    }
    pub fn prev_randao(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.prev_randao,
            Self::Capella(inner) => &inner.prev_randao,
            Self::Deneb(inner) => &inner.prev_randao,
        }
    }
    pub fn prev_randao_mut(&mut self) -> &mut Bytes32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.prev_randao,
            Self::Capella(inner) => &mut inner.prev_randao,
            Self::Deneb(inner) => &mut inner.prev_randao,
        }
    }
    pub fn block_number(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.block_number,
            Self::Capella(inner) => inner.block_number,
            Self::Deneb(inner) => inner.block_number,
        }
    }
    pub fn block_number_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.block_number,
            Self::Capella(inner) => &mut inner.block_number,
            Self::Deneb(inner) => &mut inner.block_number,
        }
    }
    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.gas_limit,
            Self::Capella(inner) => inner.gas_limit,
            Self::Deneb(inner) => inner.gas_limit,
        }
    }
    pub fn gas_limit_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.gas_limit,
            Self::Capella(inner) => &mut inner.gas_limit,
            Self::Deneb(inner) => &mut inner.gas_limit,
        }
    }
    pub fn gas_used(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.gas_used,
            Self::Capella(inner) => inner.gas_used,
            Self::Deneb(inner) => inner.gas_used,
        }
    }
    pub fn gas_used_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.gas_used,
            Self::Capella(inner) => &mut inner.gas_used,
            Self::Deneb(inner) => &mut inner.gas_used,
        }
    }
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.timestamp,
            Self::Capella(inner) => inner.timestamp,
            Self::Deneb(inner) => inner.timestamp,
        }
    }
    pub fn timestamp_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.timestamp,
            Self::Capella(inner) => &mut inner.timestamp,
            Self::Deneb(inner) => &mut inner.timestamp,
        }
    }
    pub fn extra_data(&self) -> &ByteList<MAX_EXTRA_DATA_BYTES> {
        match self {
            Self::Bellatrix(inner) => &inner.extra_data,
            Self::Capella(inner) => &inner.extra_data,
            Self::Deneb(inner) => &inner.extra_data,
        }
    }
    pub fn extra_data_mut(&mut self) -> &mut ByteList<MAX_EXTRA_DATA_BYTES> {
        match self {
            Self::Bellatrix(inner) => &mut inner.extra_data,
            Self::Capella(inner) => &mut inner.extra_data,
            Self::Deneb(inner) => &mut inner.extra_data,
        }
    }
    pub fn base_fee_per_gas(&self) -> &U256 {
        match self {
            Self::Bellatrix(inner) => &inner.base_fee_per_gas,
            Self::Capella(inner) => &inner.base_fee_per_gas,
            Self::Deneb(inner) => &inner.base_fee_per_gas,
        }
    }
    pub fn base_fee_per_gas_mut(&mut self) -> &mut U256 {
        match self {
            Self::Bellatrix(inner) => &mut inner.base_fee_per_gas,
            Self::Capella(inner) => &mut inner.base_fee_per_gas,
            Self::Deneb(inner) => &mut inner.base_fee_per_gas,
        }
    }
    pub fn block_hash(&self) -> &Hash32 {
        match self {
            Self::Bellatrix(inner) => &inner.block_hash,
            Self::Capella(inner) => &inner.block_hash,
            Self::Deneb(inner) => &inner.block_hash,
        }
    }
    pub fn block_hash_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.block_hash,
            Self::Capella(inner) => &mut inner.block_hash,
            Self::Deneb(inner) => &mut inner.block_hash,
        }
    }
    pub fn transactions_root(&self) -> Root {
        match self {
            Self::Bellatrix(inner) => inner.transactions_root,
            Self::Capella(inner) => inner.transactions_root,
            Self::Deneb(inner) => inner.transactions_root,
        }
    }
    pub fn transactions_root_mut(&mut self) -> &mut Root {
        match self {
            Self::Bellatrix(inner) => &mut inner.transactions_root,
            Self::Capella(inner) => &mut inner.transactions_root,
            Self::Deneb(inner) => &mut inner.transactions_root,
        }
    }
    pub fn withdrawals_root(&self) -> Option<Root> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.withdrawals_root),
            Self::Deneb(inner) => Some(inner.withdrawals_root),
        }
    }
    pub fn withdrawals_root_mut(&mut self) -> Option<&mut Root> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.withdrawals_root),
            Self::Deneb(inner) => Some(&mut inner.withdrawals_root),
        }
    }
    pub fn blob_gas_used(&self) -> Option<u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(inner.blob_gas_used),
        }
    }
    pub fn blob_gas_used_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(&mut inner.blob_gas_used),
        }
    }
    pub fn excess_blob_gas(&self) -> Option<u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(inner.excess_blob_gas),
        }
    }
    pub fn excess_blob_gas_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(&mut inner.excess_blob_gas),
        }
    }
}
impl<'de, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    serde::Deserialize<'de> for ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Deneb(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Capella(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Bellatrix(inner));
        }
        Err(serde::de::Error::custom(
            "no variant could be deserialized from input",
        ))
    }
}
#[derive(Debug, PartialEq, Eq, HashTreeRoot)]
#[ssz(transparent)]
pub enum ExecutionPayloadHeaderRef<
    'a,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    Bellatrix(&'a bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
    Capella(&'a capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
    Deneb(&'a deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    ExecutionPayloadHeaderRef<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    pub fn bellatrix(
        &self,
    ) -> Option<&bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella(
        &self,
    ) -> Option<&capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb(
        &self,
    ) -> Option<&deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn version(&self) -> Version {
        match self {
            Self::Bellatrix(_) => Version::Bellatrix,
            Self::Capella(_) => Version::Capella,
            Self::Deneb(_) => Version::Deneb,
        }
    }
    pub fn parent_hash(&self) -> &Hash32 {
        match self {
            Self::Bellatrix(inner) => &inner.parent_hash,
            Self::Capella(inner) => &inner.parent_hash,
            Self::Deneb(inner) => &inner.parent_hash,
        }
    }
    pub fn fee_recipient(&self) -> &ExecutionAddress {
        match self {
            Self::Bellatrix(inner) => &inner.fee_recipient,
            Self::Capella(inner) => &inner.fee_recipient,
            Self::Deneb(inner) => &inner.fee_recipient,
        }
    }
    pub fn state_root(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.state_root,
            Self::Capella(inner) => &inner.state_root,
            Self::Deneb(inner) => &inner.state_root,
        }
    }
    pub fn receipts_root(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.receipts_root,
            Self::Capella(inner) => &inner.receipts_root,
            Self::Deneb(inner) => &inner.receipts_root,
        }
    }
    pub fn logs_bloom(&self) -> &ByteVector<BYTES_PER_LOGS_BLOOM> {
        match self {
            Self::Bellatrix(inner) => &inner.logs_bloom,
            Self::Capella(inner) => &inner.logs_bloom,
            Self::Deneb(inner) => &inner.logs_bloom,
        }
    }
    pub fn prev_randao(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.prev_randao,
            Self::Capella(inner) => &inner.prev_randao,
            Self::Deneb(inner) => &inner.prev_randao,
        }
    }
    pub fn block_number(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.block_number,
            Self::Capella(inner) => inner.block_number,
            Self::Deneb(inner) => inner.block_number,
        }
    }
    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.gas_limit,
            Self::Capella(inner) => inner.gas_limit,
            Self::Deneb(inner) => inner.gas_limit,
        }
    }
    pub fn gas_used(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.gas_used,
            Self::Capella(inner) => inner.gas_used,
            Self::Deneb(inner) => inner.gas_used,
        }
    }
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.timestamp,
            Self::Capella(inner) => inner.timestamp,
            Self::Deneb(inner) => inner.timestamp,
        }
    }
    pub fn extra_data(&self) -> &ByteList<MAX_EXTRA_DATA_BYTES> {
        match self {
            Self::Bellatrix(inner) => &inner.extra_data,
            Self::Capella(inner) => &inner.extra_data,
            Self::Deneb(inner) => &inner.extra_data,
        }
    }
    pub fn base_fee_per_gas(&self) -> &U256 {
        match self {
            Self::Bellatrix(inner) => &inner.base_fee_per_gas,
            Self::Capella(inner) => &inner.base_fee_per_gas,
            Self::Deneb(inner) => &inner.base_fee_per_gas,
        }
    }
    pub fn block_hash(&self) -> &Hash32 {
        match self {
            Self::Bellatrix(inner) => &inner.block_hash,
            Self::Capella(inner) => &inner.block_hash,
            Self::Deneb(inner) => &inner.block_hash,
        }
    }
    pub fn transactions_root(&self) -> Root {
        match self {
            Self::Bellatrix(inner) => inner.transactions_root,
            Self::Capella(inner) => inner.transactions_root,
            Self::Deneb(inner) => inner.transactions_root,
        }
    }
    pub fn withdrawals_root(&self) -> Option<Root> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.withdrawals_root),
            Self::Deneb(inner) => Some(inner.withdrawals_root),
        }
    }
    pub fn blob_gas_used(&self) -> Option<u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(inner.blob_gas_used),
        }
    }
    pub fn excess_blob_gas(&self) -> Option<u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(inner.excess_blob_gas),
        }
    }
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<&'a bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    for ExecutionPayloadHeaderRef<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        value: &'a bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    ) -> Self {
        Self::Bellatrix(value)
    }
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<&'a capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    for ExecutionPayloadHeaderRef<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        value: &'a capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    ) -> Self {
        Self::Capella(value)
    }
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<&'a deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    for ExecutionPayloadHeaderRef<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        value: &'a deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    ) -> Self {
        Self::Deneb(value)
    }
}
#[derive(Debug, PartialEq, Eq, HashTreeRoot)]
#[ssz(transparent)]
pub enum ExecutionPayloadHeaderRefMut<
    'a,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    Bellatrix(
        &'a mut bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    ),
    Capella(&'a mut capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
    Deneb(&'a mut deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>),
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    ExecutionPayloadHeaderRefMut<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    pub fn bellatrix(
        &self,
    ) -> Option<&bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn bellatrix_mut(
        &mut self,
    ) -> Option<&mut bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Bellatrix(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella(
        &self,
    ) -> Option<&capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn capella_mut(
        &mut self,
    ) -> Option<&mut capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Capella(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb(
        &self,
    ) -> Option<&deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>> {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn deneb_mut(
        &mut self,
    ) -> Option<&mut deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    {
        match self {
            Self::Deneb(inner) => Some(inner),
            _ => None,
        }
    }
    pub fn version(&self) -> Version {
        match self {
            Self::Bellatrix(_) => Version::Bellatrix,
            Self::Capella(_) => Version::Capella,
            Self::Deneb(_) => Version::Deneb,
        }
    }
    pub fn parent_hash(&self) -> &Hash32 {
        match self {
            Self::Bellatrix(inner) => &inner.parent_hash,
            Self::Capella(inner) => &inner.parent_hash,
            Self::Deneb(inner) => &inner.parent_hash,
        }
    }
    pub fn parent_hash_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.parent_hash,
            Self::Capella(inner) => &mut inner.parent_hash,
            Self::Deneb(inner) => &mut inner.parent_hash,
        }
    }
    pub fn fee_recipient(&self) -> &ExecutionAddress {
        match self {
            Self::Bellatrix(inner) => &inner.fee_recipient,
            Self::Capella(inner) => &inner.fee_recipient,
            Self::Deneb(inner) => &inner.fee_recipient,
        }
    }
    pub fn fee_recipient_mut(&mut self) -> &mut ExecutionAddress {
        match self {
            Self::Bellatrix(inner) => &mut inner.fee_recipient,
            Self::Capella(inner) => &mut inner.fee_recipient,
            Self::Deneb(inner) => &mut inner.fee_recipient,
        }
    }
    pub fn state_root(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.state_root,
            Self::Capella(inner) => &inner.state_root,
            Self::Deneb(inner) => &inner.state_root,
        }
    }
    pub fn state_root_mut(&mut self) -> &mut Bytes32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.state_root,
            Self::Capella(inner) => &mut inner.state_root,
            Self::Deneb(inner) => &mut inner.state_root,
        }
    }
    pub fn receipts_root(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.receipts_root,
            Self::Capella(inner) => &inner.receipts_root,
            Self::Deneb(inner) => &inner.receipts_root,
        }
    }
    pub fn receipts_root_mut(&mut self) -> &mut Bytes32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.receipts_root,
            Self::Capella(inner) => &mut inner.receipts_root,
            Self::Deneb(inner) => &mut inner.receipts_root,
        }
    }
    pub fn logs_bloom(&self) -> &ByteVector<BYTES_PER_LOGS_BLOOM> {
        match self {
            Self::Bellatrix(inner) => &inner.logs_bloom,
            Self::Capella(inner) => &inner.logs_bloom,
            Self::Deneb(inner) => &inner.logs_bloom,
        }
    }
    pub fn logs_bloom_mut(&mut self) -> &mut ByteVector<BYTES_PER_LOGS_BLOOM> {
        match self {
            Self::Bellatrix(inner) => &mut inner.logs_bloom,
            Self::Capella(inner) => &mut inner.logs_bloom,
            Self::Deneb(inner) => &mut inner.logs_bloom,
        }
    }
    pub fn prev_randao(&self) -> &Bytes32 {
        match self {
            Self::Bellatrix(inner) => &inner.prev_randao,
            Self::Capella(inner) => &inner.prev_randao,
            Self::Deneb(inner) => &inner.prev_randao,
        }
    }
    pub fn prev_randao_mut(&mut self) -> &mut Bytes32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.prev_randao,
            Self::Capella(inner) => &mut inner.prev_randao,
            Self::Deneb(inner) => &mut inner.prev_randao,
        }
    }
    pub fn block_number(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.block_number,
            Self::Capella(inner) => inner.block_number,
            Self::Deneb(inner) => inner.block_number,
        }
    }
    pub fn block_number_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.block_number,
            Self::Capella(inner) => &mut inner.block_number,
            Self::Deneb(inner) => &mut inner.block_number,
        }
    }
    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.gas_limit,
            Self::Capella(inner) => inner.gas_limit,
            Self::Deneb(inner) => inner.gas_limit,
        }
    }
    pub fn gas_limit_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.gas_limit,
            Self::Capella(inner) => &mut inner.gas_limit,
            Self::Deneb(inner) => &mut inner.gas_limit,
        }
    }
    pub fn gas_used(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.gas_used,
            Self::Capella(inner) => inner.gas_used,
            Self::Deneb(inner) => inner.gas_used,
        }
    }
    pub fn gas_used_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.gas_used,
            Self::Capella(inner) => &mut inner.gas_used,
            Self::Deneb(inner) => &mut inner.gas_used,
        }
    }
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Bellatrix(inner) => inner.timestamp,
            Self::Capella(inner) => inner.timestamp,
            Self::Deneb(inner) => inner.timestamp,
        }
    }
    pub fn timestamp_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(inner) => &mut inner.timestamp,
            Self::Capella(inner) => &mut inner.timestamp,
            Self::Deneb(inner) => &mut inner.timestamp,
        }
    }
    pub fn extra_data(&self) -> &ByteList<MAX_EXTRA_DATA_BYTES> {
        match self {
            Self::Bellatrix(inner) => &inner.extra_data,
            Self::Capella(inner) => &inner.extra_data,
            Self::Deneb(inner) => &inner.extra_data,
        }
    }
    pub fn extra_data_mut(&mut self) -> &mut ByteList<MAX_EXTRA_DATA_BYTES> {
        match self {
            Self::Bellatrix(inner) => &mut inner.extra_data,
            Self::Capella(inner) => &mut inner.extra_data,
            Self::Deneb(inner) => &mut inner.extra_data,
        }
    }
    pub fn base_fee_per_gas(&self) -> &U256 {
        match self {
            Self::Bellatrix(inner) => &inner.base_fee_per_gas,
            Self::Capella(inner) => &inner.base_fee_per_gas,
            Self::Deneb(inner) => &inner.base_fee_per_gas,
        }
    }
    pub fn base_fee_per_gas_mut(&mut self) -> &mut U256 {
        match self {
            Self::Bellatrix(inner) => &mut inner.base_fee_per_gas,
            Self::Capella(inner) => &mut inner.base_fee_per_gas,
            Self::Deneb(inner) => &mut inner.base_fee_per_gas,
        }
    }
    pub fn block_hash(&self) -> &Hash32 {
        match self {
            Self::Bellatrix(inner) => &inner.block_hash,
            Self::Capella(inner) => &inner.block_hash,
            Self::Deneb(inner) => &inner.block_hash,
        }
    }
    pub fn block_hash_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(inner) => &mut inner.block_hash,
            Self::Capella(inner) => &mut inner.block_hash,
            Self::Deneb(inner) => &mut inner.block_hash,
        }
    }
    pub fn transactions_root(&self) -> Root {
        match self {
            Self::Bellatrix(inner) => inner.transactions_root,
            Self::Capella(inner) => inner.transactions_root,
            Self::Deneb(inner) => inner.transactions_root,
        }
    }
    pub fn transactions_root_mut(&mut self) -> &mut Root {
        match self {
            Self::Bellatrix(inner) => &mut inner.transactions_root,
            Self::Capella(inner) => &mut inner.transactions_root,
            Self::Deneb(inner) => &mut inner.transactions_root,
        }
    }
    pub fn withdrawals_root(&self) -> Option<Root> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(inner.withdrawals_root),
            Self::Deneb(inner) => Some(inner.withdrawals_root),
        }
    }
    pub fn withdrawals_root_mut(&mut self) -> Option<&mut Root> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(inner) => Some(&mut inner.withdrawals_root),
            Self::Deneb(inner) => Some(&mut inner.withdrawals_root),
        }
    }
    pub fn blob_gas_used(&self) -> Option<u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(inner.blob_gas_used),
        }
    }
    pub fn blob_gas_used_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(&mut inner.blob_gas_used),
        }
    }
    pub fn excess_blob_gas(&self) -> Option<u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(inner.excess_blob_gas),
        }
    }
    pub fn excess_blob_gas_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(inner) => Some(&mut inner.excess_blob_gas),
        }
    }
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<&'a mut bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    for ExecutionPayloadHeaderRefMut<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        value: &'a mut bellatrix::ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ) -> Self {
        Self::Bellatrix(value)
    }
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<&'a mut capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    for ExecutionPayloadHeaderRefMut<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        value: &'a mut capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    ) -> Self {
        Self::Capella(value)
    }
}
impl<'a, const BYTES_PER_LOGS_BLOOM: usize, const MAX_EXTRA_DATA_BYTES: usize>
    From<&'a mut deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>
    for ExecutionPayloadHeaderRefMut<'a, BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>
{
    fn from(
        value: &'a mut deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    ) -> Self {
        Self::Deneb(value)
    }
}
