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

/// A type pointing at a contract using the environment and contract address initialized with. This
/// contract is not typesafe, be sure the contract deployed at the address matches the ABI you use
/// to make calls.
///
/// To preflight calls in the host to build the proof, use [Contract::preflight], using the env
/// from [EthViewCallEnv::from_rpc] or [ViewCallEnv::new].
///
/// To initialize in the guest, use [Contract::new], with the environment constructed through
/// [ViewCallInput::into_env].
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
    P: Provider,
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
    fn new_sol(env: E, address: Address, call: &C) -> Self
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
    P: Provider,
    H: EvmHeader,
    C: SolCall,
{
    /// Executes the call with a [ViewCallEnv] constructed with [ViewCallEnv::preflight].
    pub fn call(self) -> anyhow::Result<C::Return> {
        let evm = new_evm(&mut self.env.db, self.env.cfg_env.clone(), &self.env.header);
        self.transaction
            .transact(evm)
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
        let evm = new_evm(
            WrapStateDb::new(&self.env.db),
            self.env.cfg_env.clone(),
            &self.env.header,
        );
        self.transaction.transact(evm).unwrap()
    }
}

/// A builder for calling an Ethereum contract.
#[derive(Debug, Clone)]
pub struct ViewCall<C> {
    data: Vec<u8>,
    pub(crate) contract: Address,
    pub(crate) caller: Address,
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
    pub(crate) fn transact<DB>(self, mut evm: Evm<'_, (), DB>) -> Result<C::Return, String>
    where
        C: SolCall,
        DB: Database,
        <DB as Database>::Error: Debug,
    {
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

pub(crate) fn new_evm<'a, DB, H>(
    db: DB,
    cfg: CfgEnvWithHandlerCfg,
    header: &Sealed<H>,
) -> Evm<'a, (), DB>
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
