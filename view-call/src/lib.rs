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

use alloy_primitives::{
    b256, keccak256, Address, BlockNumber, Bytes, Sealable, Sealed, TxNumber, B256, U256,
};
use alloy_rlp_derive::{RlpDecodable, RlpEncodable};
use alloy_sol_types::{sol, SolCall, SolType};
use revm::{
    primitives::{
        db::Database, AccountInfo, BlockEnv, Bytecode, CfgEnvWithHandlerCfg, ExecutionResult,
        HashMap, ResultAndState, SpecId, SuccessReason, TransactTo,
    },
    Evm,
};
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, fmt::Debug, rc::Rc};

pub mod config;
pub mod db;
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
    pub fn into_env(self) -> ViewCallEnv<StateDB, H> {
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

/// The [ViewCall] is configured from this object.
pub struct ViewCallEnv<D: Database, H: EvmHeader> {
    db: D,
    cfg_env: CfgEnvWithHandlerCfg,
    header: Sealed<H>,
}

impl<D: Database, H: EvmHeader> ViewCallEnv<D, H> {
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

/// A view call to an Ethereum contract.
pub struct ViewCall<C: SolCall> {
    call: C,
    contract: Address,
    caller: Address,
}

impl<C: SolCall> ViewCall<C> {
    /// The default gas limit for view calls.
    const GAS_LIMIT: u64 = 30_000_000;

    /// Creates a new view call to the given contract.
    pub fn new(call: C, contract: Address) -> Self {
        Self {
            call,
            contract,
            caller: contract,
        }
    }

    /// Sets the caller of the view function.
    pub fn with_caller(mut self, caller: Address) -> Self {
        self.caller = caller;
        self
    }

    /// Executes the view call using the given environment.
    #[inline]
    pub fn execute<D: Database, H: EvmHeader>(self, env: ViewCallEnv<D, H>) -> C::Return
    where
        <D as Database>::Error: Debug,
    {
        self.transact(env.db, env.cfg_env, env.header.inner())
            .unwrap()
    }

    /// Transacts a transaction corresponding to the call data.
    fn transact<D: Database, H: EvmHeader>(
        &self,
        db: D,
        cfg_env: CfgEnvWithHandlerCfg,
        header: &H,
    ) -> Result<C::Return, String>
    where
        <D as Database>::Error: Debug,
    {
        let mut evm = Evm::builder()
            .with_db(db)
            .with_cfg_env_with_handler_cfg(cfg_env)
            .modify_block_env(|blk_env| header.fill_block_env(blk_env))
            .build();

        let tx_env = evm.tx_mut();
        tx_env.caller = self.caller;
        tx_env.gas_limit = Self::GAS_LIMIT;
        tx_env.transact_to = TransactTo::call(self.contract);
        tx_env.value = U256::ZERO;
        tx_env.data = self.call.abi_encode().into();

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

    account_storage: HashMap<Address, Option<Rc<MerkleTrie>>>,
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
            account_storage: HashMap::new(),
        }
    }
}

impl Database for StateDB {
    /// The database does not return any errors.
    type Error = Infallible;

    #[inline]
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let account = self
            .state_trie
            .get_rlp::<StateAccount>(keccak256(address))
            .expect("invalid state value");
        match account {
            Some(account) => {
                // link storage trie to the account, if it exists
                if let Some(storage_trie) = self.storage_tries.get(&account.storage_root) {
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

    #[inline]
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        let code = self
            .contracts
            .get(&hash)
            .unwrap_or_else(|| panic!("code not found: {}", hash));
        Ok(Bytecode::new_raw(code.clone()))
    }

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

    #[inline]
    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        // block number is never bigger then u64::MAX
        let number: u64 = number.to();
        let hash = self
            .block_hashes
            .get(&number)
            .unwrap_or_else(|| panic!("block not found: {}", number));
        Ok(*hash)
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
