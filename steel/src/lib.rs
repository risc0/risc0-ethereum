// Copyright 2024 RISC Zero, Inc.
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

#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_primitives::{
    b256, keccak256, Address, BlockNumber, Bytes, Sealable, Sealed, TxNumber, B256, U256,
};
use alloy_rlp_derive::{RlpDecodable, RlpEncodable};
use alloy_sol_types::{sol, SolCall, SolType};
#[cfg(feature = "host")]
use host::db::ProofDb;
use revm::{
    primitives::{
        AccountInfo, BlockEnv, Bytecode, CfgEnvWithHandlerCfg, ExecutionResult, HashMap,
        ResultAndState, SpecId, SuccessReason, TransactTo,
    },
    Database, Evm,
};
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, fmt::Debug, marker::PhantomData, mem, rc::Rc};

pub mod config;
pub mod ethereum;
#[cfg(feature = "host")]
pub mod host;
mod mpt;

pub use mpt::MerkleTrie;

/// The serializable input to derive and validate a [ViewCallEnv].
#[derive(Debug, Serialize, Deserialize)]
pub struct ViewCallInput<H> {
    pub header: H,
    pub state_trie: MerkleTrie,
    pub storage_tries: Vec<MerkleTrie>,
    pub contracts: Vec<Bytes>,
    pub ancestors: Vec<H>,
}

impl<H: EvmHeader> ViewCallInput<H> {
    /// Converts the input into a [ViewCallEnv] for execution.
    ///
    /// This method verifies that the state matches the state root in the header and panics if not.
    pub fn into_env(self) -> GuestViewCallEnv<H> {
        // verify that the state root matches the state trie
        let state_root = self.state_trie.hash_slow();
        assert_eq!(self.header.state_root(), &state_root, "State root mismatch");

        // seal the header to compute its block hash
        let header = self.header.seal_slow();

        // validate that ancestor headers form a valid chain
        let mut block_hashes = HashMap::with_capacity(self.ancestors.len() + 1);
        block_hashes.insert(header.number(), header.seal());

        let mut previous_header = header.inner();
        for ancestor in &self.ancestors {
            let ancestor_hash = ancestor.hash_slow();
            assert_eq!(
                previous_header.parent_hash(),
                &ancestor_hash,
                "Invalid chain: block {} is not the parent of block {}",
                ancestor.number(),
                previous_header.number()
            );
            block_hashes.insert(ancestor.number(), ancestor_hash);
            previous_header = ancestor;
        }

        let db = StateDB::new(
            self.state_trie,
            self.storage_tries,
            self.contracts,
            block_hashes,
        );

        ViewCallEnv::new(db, header)
    }
}

sol! {
    /// Solidity struct representing the committed block used for validation.
    struct BlockCommitment {
        bytes32 blockHash;
        uint blockNumber;
    }
}

#[cfg(feature = "host")]
type HostViewCallEnv<P, H> = ViewCallEnv<ProofDb<P>, H>;
pub type GuestViewCallEnv<H> = ViewCallEnv<StateDB, H>;

/// The [ViewCall] is configured from this object.
pub struct ViewCallEnv<D, H> {
    db: D,
    cfg_env: CfgEnvWithHandlerCfg,
    header: Sealed<H>,
}

impl<D, H: EvmHeader> ViewCallEnv<D, H> {
    /// Creates a new view call environment.
    /// It uses the default configuration for the latest specification.
    pub fn new(db: D, header: Sealed<H>) -> Self {
        let cfg_env = CfgEnvWithHandlerCfg::new_with_spec_id(Default::default(), SpecId::LATEST);

        Self {
            db,
            cfg_env,
            header,
        }
    }

    /// Sets the chain ID and specification ID from the given chain spec.
    pub fn with_chain_spec(mut self, chain_spec: &config::ChainSpec) -> Self {
        self.cfg_env.chain_id = chain_spec.chain_id();
        self.cfg_env.handler_cfg.spec_id = chain_spec
            .active_fork(self.header.number(), self.header.timestamp())
            .unwrap();
        self
    }

    /// Returns the [BlockCommitment] used to validate the environment.
    pub fn block_commitment(&self) -> BlockCommitment {
        BlockCommitment {
            blockHash: self.header.seal(),
            blockNumber: U256::from(self.header.number()),
        }
    }

    /// Returns the header of the environment.
    pub fn header(&self) -> &H {
        self.header.inner()
    }
}

pub(crate) mod private {
    use super::*;

    pub trait SteelEnv<'a> {
        type Ext;
        type Db: revm::Database;
        fn into_evm<'b: 'a>(self) -> Evm<'b, Self::Ext, Self::Db>
        where
            <Self::Db as Database>::Error: Debug;
    }

    impl<'a, H> SteelEnv<'a> for &'a GuestViewCallEnv<H>
    where
        H: EvmHeader,
    {
        type Ext = ();

        type Db = WrapStateDb<'a>;

        fn into_evm<'b: 'a>(self) -> Evm<'b, Self::Ext, Self::Db> {
            Evm::builder()
                .with_db(WrapStateDb::new(&self.db))
                .with_cfg_env_with_handler_cfg(self.cfg_env.clone())
                .modify_block_env(|blk_env| self.header.fill_block_env(blk_env))
                .build()
        }
    }

    pub struct WrapStateDb<'a> {
        inner: &'a StateDB,
        account_storage: HashMap<Address, Option<Rc<MerkleTrie>>>,
    }

    impl<'a> WrapStateDb<'a> {
        /// Creates a new [Database] from the given [StateDb].
        pub(crate) fn new(inner: &'a StateDB) -> Self {
            Self {
                inner,
                account_storage: HashMap::new(),
            }
        }
    }

    impl Database for WrapStateDb<'_> {
        /// The database does not return any errors.
        type Error = Infallible;

        /// Get basic account information.
        #[inline]
        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            let account = self.inner.account(address);
            match account {
                Some(account) => {
                    // link storage trie to the account, if it exists
                    if let Some(storage_trie) = self.inner.storage_trie(&account.storage_root) {
                        self.account_storage
                            .insert(address, Some(storage_trie.clone()));
                    }

                    Ok(Some(AccountInfo {
                        balance: account.balance,
                        nonce: account.nonce,
                        code_hash: account.code_hash,
                        code: None, // we don't need the code here, `code_by_hash` will be used instead
                    }))
                }
                None => {
                    self.account_storage.insert(address, None);

                    Ok(None)
                }
            }
        }

        /// Get account code by its hash.
        #[inline]
        fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
            let code = self.inner.code_by_hash(code_hash);
            Ok(Bytecode::new_raw(code.clone()))
        }

        /// Get storage value of address at index.
        #[inline]
        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            let storage = self
                .account_storage
                .get(&address)
                .unwrap_or_else(|| panic!("storage not found: {:?}", address));
            match storage {
                Some(storage) => {
                    let val = storage
                        .get_rlp(keccak256(index.to_be_bytes::<32>()))
                        .expect("invalid storage value");
                    Ok(val.unwrap_or_default())
                }
                None => Ok(U256::ZERO),
            }
        }

        /// Get block hash by block number.
        #[inline]
        fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
            Ok(self.inner.block_hash(number))
        }
    }
}

/// A type pointing at a contract using the environment and contract address initialized with. This
/// contract is not typesafe, be sure the contract deployed at the address matches the ABI you use
/// to make calls.
///
/// To preflight calls in the host to build the proof, use [Contract::preflight], using the env
/// from [EthViewCallEnv::from_rpc].
///
/// To initialize in the guest, use [Contract::new], with the environment constructed through
/// [EthViewCallInput::into_env].
///
/// # Examples
///
/// ```no_run
/// use risc0_steel::{ethereum::EthViewCallEnv, Contract};
/// use alloy_primitives::{address};
/// use alloy_sol_types::sol;
///
/// # fn main() -> anyhow::Result<()> {
/// let contract_address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
/// sol! {
/// #[derive(Debug, PartialEq, Eq)]
/// interface IERC20 {
///    function balanceOf(address account) external view returns (uint);
/// }
/// }
///
/// let get_balance = IERC20::balanceOfCall {
///     account: address!("F977814e90dA44bFA03b6295A0616a897441aceC"),
/// };
///
/// // Host:
///
/// let mut env = EthViewCallEnv::from_rpc("https://ethereum-rpc.publicnode.com", None)?;
/// let mut contract = Contract::preflight(contract_address, &mut env);
/// contract.call_builder(&get_balance).call()?;
///
/// let view_call_input = env.into_zkvm_input()?;
///
/// // Guest
///
/// let view_call_env = view_call_input.into_env();
/// let contract = Contract::new(contract_address, &view_call_env);
/// contract.call_builder(&get_balance).call();
///
/// # Ok(())
/// # }
/// ```
///
/// [EthViewCallInput::into_env]: ethereum::EthViewCallInput::into_env
/// [EthViewCallEnv::from_rpc]: ethereum::EthViewCallEnv::from_rpc
pub struct Contract<E> {
    address: Address,
    env: E,
}

impl<'a, H> Contract<&'a GuestViewCallEnv<H>> {
    pub fn new(address: Address, env: &'a GuestViewCallEnv<H>) -> Self {
        Self { address, env }
    }

    /// Initialize a call builder to execute a call on the contract. For more information on usage,
    /// see [Contract].
    pub fn call_builder<C: SolCall>(&self, call: &C) -> ViewCallBuilder<&GuestViewCallEnv<H>, C> {
        ViewCallBuilder::new_sol(self.env, self.address, call)
    }
}

#[cfg(feature = "host")]
impl<'a, P, H> Contract<&'a mut HostViewCallEnv<P, H>>
where
    P: host::provider::Provider,
{
    /// Constructor to initialize a [ViewCallEnv] outside of the guest program. When calling
    /// functions on the contract, the data needed will be fetched through the [Provider], and
    /// a storage proof of any elements accessed will be generated in
    /// [ViewCallEnv::into_zkvm_input].
    ///
    /// [Provider]: host::provider::Provider
    pub fn preflight(address: Address, env: &'a mut HostViewCallEnv<P, H>) -> Self {
        Self { address, env }
    }

    /// Initialize a call builder to execute a call on the contract. For more information on usage,
    /// see [Contract].
    pub fn call_builder<C: SolCall>(
        &mut self,
        call: &C,
    ) -> ViewCallBuilder<&mut HostViewCallEnv<P, H>, C> {
        ViewCallBuilder::new_sol(&mut self.env, self.address, call)
    }
}

/// A builder for calling an Ethereum contract. Once configured, call with [ViewCallBuilder::call].
#[derive(Debug, Clone)]
#[must_use]
pub struct ViewCallBuilder<E, C> {
    transaction: ViewCall<C>,
    env: E,
}

impl<E, C> ViewCallBuilder<E, C> {
    /// The default gas limit for function calls.
    const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

    /// Creates a new view call to the given contract.
    ///
    /// Note: Intentionally not exposing, but will be needed with generic contract codegen.
    pub(crate) fn new_sol(env: E, address: Address, call: &C) -> Self
    where
        C: SolCall,
    {
        let data = call.abi_encode();
        let transaction = ViewCall {
            data,
            contract: address,
            caller: address,
            gas_limit: Self::DEFAULT_GAS_LIMIT,
            gas_price: U256::ZERO,
            value: U256::ZERO,
            call_ty: PhantomData::<C>,
        };
        Self { transaction, env }
    }

    /// Sets the caller of the function call.
    pub fn from(mut self, from: Address) -> Self {
        self.transaction.caller = from;
        self
    }

    /// Sets the gas limit of the function call.
    pub fn gas(mut self, gas: u64) -> Self {
        self.transaction.gas_limit = gas;
        self
    }

    /// Sets the gas price of the function call.
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.transaction.gas_price = gas_price;
        self
    }

    /// Sets the value field of the function call.
    pub fn value(mut self, value: U256) -> Self {
        self.transaction.value = value;
        self
    }
}

#[cfg(feature = "host")]
impl<'a, P, H, C> ViewCallBuilder<&'a mut HostViewCallEnv<P, H>, C>
where
    P: host::provider::Provider,
    H: EvmHeader,
    C: SolCall,
{
    /// Executes the call with a [ViewCallEnv] constructed with [ViewCallEnv::preflight].
    pub fn call(self) -> anyhow::Result<C::Return> {
        self.transaction
            .transact(self.env)
            .map_err(|err| anyhow::anyhow!(err))
    }
}

impl<'a, H, C> ViewCallBuilder<&'a GuestViewCallEnv<H>, C>
where
    H: EvmHeader,
    C: SolCall,
{
    /// Executes the call with a [ViewCallEnv] constructed with [ViewCallEnv::preflight].
    pub fn call(self) -> C::Return {
        self.transaction.transact(self.env).unwrap()
    }
}

/// A builder for calling an Ethereum contract.
#[derive(Debug, Clone)]
pub struct ViewCall<C> {
    data: Vec<u8>,
    contract: Address,
    caller: Address,
    gas_limit: u64,
    gas_price: U256,
    value: U256,
    call_ty: PhantomData<C>,
}

impl<C: SolCall> ViewCall<C> {
    /// Compile-time assertion that the call C has a return value.
    const RETURNS: () = assert!(
        mem::size_of::<C::Return>() > 0,
        "Function call must have a return value"
    );
    /// The default gas limit for function calls.
    const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

    /// Creates a new view call to the given contract.
    #[deprecated(since = "0.11.0", note = "please use `Contract::call_builder` instead")]
    pub fn new(call: C, contract: Address) -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = Self::RETURNS;

        let data = call.abi_encode();

        Self {
            data,
            contract,
            caller: contract,
            gas_limit: Self::DEFAULT_GAS_LIMIT,
            gas_price: U256::ZERO,
            value: U256::ZERO,
            call_ty: PhantomData::<C>,
        }
    }

    /// Sets the caller of the function call.
    #[deprecated(
        since = "0.11.0",
        note = "please use `.from(..)` (ViewCall::from) instead"
    )]
    pub fn with_caller(mut self, caller: Address) -> Self {
        self.caller = caller;
        self
    }

    /// Sets the caller of the function call.
    pub fn from(mut self, from: Address) -> Self {
        self.caller = from;
        self
    }

    /// Sets the gas limit of the function call.
    pub fn gas(mut self, gas: u64) -> Self {
        self.gas_limit = gas;
        self
    }

    /// Sets the gas price of the function call.
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = gas_price;
        self
    }

    /// Sets the value field of the function call.
    pub fn value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    /// Executes the view call using the given environment.
    #[inline]
    #[deprecated(since = "0.11.0", note = "please use `Contract::new` instead")]
    pub fn execute<H: EvmHeader>(self, env: GuestViewCallEnv<H>) -> C::Return {
        ViewCallBuilder {
            transaction: self,
            env: &env,
        }
        .call()
    }

    /// Executes the call for the provided state.
    fn transact<'a, E>(self, env: E) -> Result<C::Return, String>
    where
        C: SolCall,
        E: private::SteelEnv<'a> + 'a,
        <<E as private::SteelEnv<'a>>::Db as revm::Database>::Error: Debug,
    {
        let mut evm = env.into_evm();

        let tx_env = evm.tx_mut();
        tx_env.caller = self.caller;
        tx_env.gas_limit = self.gas_limit;
        tx_env.gas_price = self.gas_price;
        tx_env.transact_to = TransactTo::call(self.contract);
        tx_env.value = self.value;
        tx_env.data = self.data.into();

        let ResultAndState { result, .. } = evm
            .transact_preverified()
            .map_err(|err| format!("Call '{}' failed: {:?}", C::SIGNATURE, err))?;
        let ExecutionResult::Success { reason, output, .. } = result else {
            return Err(format!("Call '{}' failed", C::SIGNATURE));
        };
        // there must be a return value to decode
        if reason != SuccessReason::Return {
            return Err(format!(
                "Call '{}' did not return: {:?}",
                C::SIGNATURE,
                reason
            ));
        }
        let returns = C::abi_decode_returns(&output.into_data(), true).map_err(|err| {
            format!(
                "Call '{}' returned invalid type; expected '{}': {:?}",
                C::SIGNATURE,
                <C::ReturnTuple<'_> as SolType>::SOL_NAME,
                err
            )
        })?;

        Ok(returns)
    }
}

/// A simple read-only EVM database.
///
/// It is backed by a single [MerkleTrie] for the accounts and one [MerkleTrie] each for the
/// accounts' storages. It panics when data is queried that is not contained in the tries.
pub struct StateDB {
    state_trie: MerkleTrie,
    storage_tries: HashMap<B256, Rc<MerkleTrie>>,
    contracts: HashMap<B256, Bytes>,
    block_hashes: HashMap<u64, B256>,
}

impl StateDB {
    /// Creates a new state database from the given tries.
    pub fn new(
        state_trie: MerkleTrie,
        storage_tries: impl IntoIterator<Item = MerkleTrie>,
        contracts: impl IntoIterator<Item = Bytes>,
        block_hashes: HashMap<u64, B256>,
    ) -> Self {
        let contracts = contracts
            .into_iter()
            .map(|code| (keccak256(&code), code))
            .collect();
        let storage_tries = storage_tries
            .into_iter()
            .map(|trie| (trie.hash_slow(), Rc::new(trie)))
            .collect();
        Self {
            state_trie,
            contracts,
            storage_tries,
            block_hashes,
        }
    }

    fn account(&self, address: Address) -> Option<StateAccount> {
        self.state_trie
            .get_rlp(keccak256(address))
            .expect("invalid state value")
    }

    fn code_by_hash(&self, hash: B256) -> &Bytes {
        self.contracts
            .get(&hash)
            .unwrap_or_else(|| panic!("code not found: {}", hash))
    }

    fn block_hash(&self, number: U256) -> B256 {
        // block number is never bigger then u64::MAX
        let number: u64 = number.to();
        let hash = self
            .block_hashes
            .get(&number)
            .unwrap_or_else(|| panic!("block not found: {}", number));
        *hash
    }

    fn storage_trie(&self, root: &B256) -> Option<&Rc<MerkleTrie>> {
        self.storage_tries.get(root)
    }
}

/// Hash of an empty byte array, i.e. `keccak256([])`.
pub const KECCAK_EMPTY: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

/// Represents an account within the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct StateAccount {
    /// The number of transactions sent from this account's address.
    pub nonce: TxNumber,
    /// The number of Wei owned by this account's address.
    pub balance: U256,
    /// The root of the account's storage trie.
    pub storage_root: B256,
    /// The hash of the EVM code of this account.
    pub code_hash: B256,
}

impl Default for StateAccount {
    /// Provides default values for a [StateAccount].
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: mpt::EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        }
    }
}

/// An EVM abstraction of a block header.
pub trait EvmHeader: Sealable {
    /// Returns the hash of the parent block's header.
    fn parent_hash(&self) -> &B256;
    /// Returns the block number.
    fn number(&self) -> BlockNumber;
    /// Returns the block timestamp.
    fn timestamp(&self) -> u64;
    /// Returns the state root hash.
    fn state_root(&self) -> &B256;

    /// Fills the EVM block environment with the header's data.
    fn fill_block_env(&self, blk_env: &mut BlockEnv);
}
