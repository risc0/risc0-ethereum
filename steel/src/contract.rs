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

#[cfg(feature = "host")]
use crate::host::{provider::Provider, HostViewCallEnv};
use crate::{EvmHeader, GuestViewCallEnv, MerkleTrie, StateDB};
use alloy_primitives::{keccak256, Address, Sealed, B256, U256};

use alloy_sol_types::{SolCall, SolType};

use revm::{
    primitives::{
        AccountInfo, Bytecode, CfgEnvWithHandlerCfg, ExecutionResult, HashMap, ResultAndState,
        SuccessReason, TransactTo,
    },
    Database, Evm,
};
use std::{convert::Infallible, fmt::Debug, marker::PhantomData, mem, rc::Rc};

/// Represents a contract that is initialized with a specific environment and contract address.
///
/// **Note:** This contract is not type-safe. Ensure that the deployed contract at the specified
/// address matches the ABI used for making calls.
///
/// ### Usage
/// - **Preflight calls in the Host:** To prepare calls in the host environment and build the
///   necessary proof, use [Contract::preflight]. The environment can be initialized using
///   [EthViewCallEnv::from_rpc] or [ViewCallEnv::new].
/// - **Calls in the Guest:** To initialize the contract in the guest environment, use
///   [Contract::new]. The environment should be constructed using [ViewCallInput::into_env].
///
/// ### Examples
/// ```rust no_run
/// # use risc0_steel::{ethereum::EthViewCallEnv, Contract};
/// # use alloy_primitives::{address};
/// # use alloy_sol_types::sol;
///
/// # fn main() -> anyhow::Result<()> {
/// let contract_address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
/// sol! {
///     interface IERC20 {
///         function balanceOf(address account) external view returns (uint);
///     }
/// }
///
/// let get_balance = IERC20::balanceOfCall {
///     account: address!("F977814e90dA44bFA03b6295A0616a897441aceC"),
/// };
///
/// // Host:
/// let mut env = EthViewCallEnv::from_rpc("https://ethereum-rpc.publicnode.com", None)?;
/// let mut contract = Contract::preflight(contract_address, &mut env);
/// contract.call_builder(&get_balance).call()?;
///
/// let view_call_input = env.into_zkvm_input()?;
///
/// // Guest:
/// let view_call_env = view_call_input.into_env();
/// let contract = Contract::new(contract_address, &view_call_env);
/// contract.call_builder(&get_balance).call();
///
/// # Ok(())
/// # }
/// ```
///
/// [ViewCallInput::into_env]: crate::ViewCallInput::into_env
/// [ViewCallEnv::new]: crate::ViewCallEnv::new
/// [EthViewCallEnv::from_rpc]: crate::ethereum::EthViewCallEnv::from_rpc
pub struct Contract<E> {
    address: Address,
    env: E,
}

impl<'a, H> Contract<&'a GuestViewCallEnv<H>> {
    pub fn new(address: Address, env: &'a GuestViewCallEnv<H>) -> Self {
        Self { address, env }
    }

    /// Initialize a call builder to execute a call on the contract.
    ///
    /// For more information on usage, see [Contract].
    pub fn call_builder<C: SolCall>(&self, call: &C) -> CallBuilder<C, &GuestViewCallEnv<H>> {
        CallBuilder::new(self.env, self.address, call)
    }
}

#[cfg(feature = "host")]
impl<'a, P, H> Contract<&'a mut HostViewCallEnv<P, H>>
where
    P: Provider,
{
    /// Constructor to initialize a [ViewCallEnv] outside of the guest program.
    ///
    /// When calling functions on the contract, the data needed will be fetched through the
    /// [Provider], and a storage proof of any elements accessed will be generated in
    /// [ViewCallEnv::into_zkvm_input].
    ///
    /// [Provider]: crate::host::provider::Provider
    /// [ViewCallEnv::into_zkvm_input]: crate::ViewCallEnv::into_zkvm_input
    /// [ViewCallEnv]: crate::ViewCallEnv
    pub fn preflight(address: Address, env: &'a mut HostViewCallEnv<P, H>) -> Self {
        Self { address, env }
    }

    /// Initialize a call builder to execute a call on the contract.
    ///
    /// For more information on usage see [Contract].
    pub fn call_builder<C: SolCall>(
        &mut self,
        call: &C,
    ) -> CallBuilder<C, &mut HostViewCallEnv<P, H>> {
        CallBuilder::new(&mut self.env, self.address, call)
    }
}

/// A builder for calling an Ethereum contract.
///
/// Once configured, call with [CallBuilder::call].
#[derive(Debug, Clone)]
#[must_use]
pub struct CallBuilder<C, E> {
    tx: CallTxData<C>,
    env: E,
}

impl<C, E> CallBuilder<C, E> {
    /// The default gas limit for function calls.
    const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

    /// Creates a new view call to the given contract.
    fn new(env: E, address: Address, call: &C) -> Self
    where
        C: SolCall,
    {
        let tx = CallTxData {
            caller: address,
            gas_limit: Self::DEFAULT_GAS_LIMIT,
            gas_price: U256::ZERO,
            to: address,
            value: U256::ZERO,
            data: call.abi_encode(),
            phantom: PhantomData,
        };
        Self { tx, env }
    }

    /// Sets the caller of the function call.
    pub fn from(mut self, from: Address) -> Self {
        self.tx.caller = from;
        self
    }

    /// Sets the gas limit of the function call.
    pub fn gas(mut self, gas: u64) -> Self {
        self.tx.gas_limit = gas;
        self
    }

    /// Sets the gas price of the function call.
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.tx.gas_price = gas_price;
        self
    }

    /// Sets the value field of the function call.
    pub fn value(mut self, value: U256) -> Self {
        self.tx.value = value;
        self
    }
}

#[cfg(feature = "host")]
impl<'a, C, P, H> CallBuilder<C, &'a mut HostViewCallEnv<P, H>>
where
    C: SolCall,
    P: Provider,
    H: EvmHeader,
{
    /// Executes the call with a [ViewCallEnv] constructed with [Contract::preflight].
    ///
    /// [ViewCallEnv]: crate::ViewCallEnv
    pub fn call(self) -> anyhow::Result<C::Return> {
        let evm = new_evm(&mut self.env.db, self.env.cfg_env.clone(), &self.env.header);
        self.tx.transact(evm).map_err(|err| anyhow::anyhow!(err))
    }
}

impl<'a, C, H> CallBuilder<C, &'a GuestViewCallEnv<H>>
where
    C: SolCall,
    H: EvmHeader,
{
    /// Executes the call with a [ViewCallEnv] constructed with [Contract::new].
    ///
    /// [ViewCallEnv]: crate::ViewCallEnv
    pub fn call(self) -> C::Return {
        let evm = new_evm(
            WrapStateDb::new(&self.env.db),
            self.env.cfg_env.clone(),
            &self.env.header,
        );
        self.tx.transact(evm).unwrap()
    }
}

/// Transaction data to be used with [CallBuilder] for an execution.
#[derive(Debug, Clone)]
struct CallTxData<C> {
    caller: Address,
    gas_limit: u64,
    gas_price: U256,
    to: Address,
    value: U256,
    data: Vec<u8>,
    phantom: PhantomData<C>,
}

impl<C: SolCall> CallTxData<C> {
    /// Compile-time assertion that the call C has a return value.
    const RETURNS: () = assert!(
        mem::size_of::<C::Return>() > 0,
        "Function call must have a return value"
    );

    /// Executes the call in the provided [Evm].
    fn transact<DB>(self, mut evm: Evm<'_, (), DB>) -> Result<C::Return, String>
    where
        DB: Database,
        <DB as Database>::Error: Debug,
    {
        #[allow(clippy::let_unit_value)]
        let _ = Self::RETURNS;

        let tx_env = evm.tx_mut();
        tx_env.caller = self.caller;
        tx_env.gas_limit = self.gas_limit;
        tx_env.gas_price = self.gas_price;
        tx_env.transact_to = TransactTo::call(self.to);
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

fn new_evm<'a, DB, H>(db: DB, cfg: CfgEnvWithHandlerCfg, header: &Sealed<H>) -> Evm<'a, (), DB>
where
    DB: Database,
    H: EvmHeader,
{
    Evm::builder()
        .with_db(db)
        .with_cfg_env_with_handler_cfg(cfg)
        .modify_block_env(|blk_env| header.fill_block_env(blk_env))
        .build()
}

struct WrapStateDb<'a> {
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
