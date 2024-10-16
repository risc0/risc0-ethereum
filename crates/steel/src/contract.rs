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

use std::{borrow::Borrow, fmt::Debug, marker::PhantomData, mem};

use crate::{state::WrapStateDb, EvmBlockHeader, GuestEvmEnv};
use alloy_primitives::{Address, TxKind, U256};
use alloy_sol_types::{SolCall, SolType};
use anyhow::anyhow;
use revm::{
    primitives::{CfgEnvWithHandlerCfg, ExecutionResult, ResultAndState, SuccessReason},
    Database, Evm,
};

/// Represents a contract that is initialized with a specific environment and contract address.
///
/// **Note:** This contract is not type-safe. Ensure that the deployed contract at the specified
/// address matches the ABI used for making calls.
///
/// ### Usage
/// - **Preflight calls on the Host:** To prepare calls on the host environment and build the
///   necessary proof, use [Contract::preflight]. The environment can be initialized using the
///   [EthEvmEnv::builder] or [EvmEnv::builder].
/// - **Calls in the Guest:** To initialize the contract in the guest environment, use
///   [Contract::new]. The environment should be constructed using [EvmInput::into_env].
///
/// ### Examples
/// ```rust,no_run
/// # use risc0_steel::{ethereum::EthEvmEnv, Contract, host::BlockNumberOrTag};
/// # use alloy_primitives::address;
/// # use alloy_sol_types::sol;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// let contract_address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");
/// sol! {
///     interface IERC20 {
///         function balanceOf(address account) external view returns (uint);
///     }
/// }
/// let account = address!("F977814e90dA44bFA03b6295A0616a897441aceC");
/// let get_balance = IERC20::balanceOfCall { account };
///
/// // Host:
/// let url = "https://ethereum-rpc.publicnode.com".parse()?;
/// let mut env = EthEvmEnv::builder().rpc(url).build().await?;
/// let mut contract = Contract::preflight(contract_address, &mut env);
/// contract.call_builder(&get_balance).call().await?;
///
/// let evm_input = env.into_input().await?;
///
/// // Guest:
/// let evm_env = evm_input.into_env();
/// let contract = Contract::new(contract_address, &evm_env);
/// contract.call_builder(&get_balance).call();
///
/// # Ok(())
/// # }
/// ```
///
/// [EthEvmEnv::builder]: crate::ethereum::EthEvmEnv::builder
/// [EvmEnv::builder]: crate::EvmEnv::builder
/// [EvmInput::into_env]: crate::EvmInput::into_env
pub struct Contract<E> {
    address: Address,
    env: E,
}

impl<'a, H> Contract<&'a GuestEvmEnv<H>> {
    /// Constructor for executing calls to an Ethereum contract in the guest.
    pub fn new(address: Address, env: &'a GuestEvmEnv<H>) -> Self {
        Self { address, env }
    }

    /// Initializes a call builder to execute a call on the contract.
    pub fn call_builder<S: SolCall>(&self, call: &S) -> CallBuilder<S, &GuestEvmEnv<H>> {
        CallBuilder::new(self.env, self.address, call)
    }
}

/// A builder for calling an Ethereum contract.
///
/// Once configured, call with [CallBuilder::call].
#[derive(Debug, Clone)]
#[must_use]
pub struct CallBuilder<S, E> {
    tx: CallTxData<S>,
    env: E,
}

impl<S, E> CallBuilder<S, E> {
    /// The default gas limit for function calls.
    const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

    /// Creates a new builder for the given contract call.
    fn new(env: E, address: Address, call: &S) -> Self
    where
        S: SolCall,
    {
        let tx = CallTxData {
            caller: address, // by default the contract calls itself
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
mod host {
    use super::*;
    use crate::host::{
        db::{AlloyDb, ProviderDb},
        HostEvmEnv,
    };
    use alloy::{
        eips::eip2930::AccessList,
        network::{Network, TransactionBuilder},
        providers::Provider,
        transports::Transport,
    };
    use anyhow::{anyhow, Context, Result};

    impl<'a, D: Database, H, C> Contract<&'a mut HostEvmEnv<D, H, C>> {
        /// Constructor for preflighting calls to an Ethereum contract on the host.
        ///
        /// Initializes the environment for calling functions on the Ethereum contract, fetching
        /// necessary data via the [Provider], and generating a storage proof for any accessed
        /// elements using [EvmEnv::into_input].
        ///
        /// [EvmEnv::into_input]: crate::EvmEnv::into_input
        /// [EvmEnv]: crate::EvmEnv
        pub fn preflight(address: Address, env: &'a mut HostEvmEnv<D, H, C>) -> Self {
            Self { address, env }
        }

        /// Initializes a call builder to execute a call on the contract.
        pub fn call_builder<S: SolCall>(
            &mut self,
            call: &S,
        ) -> CallBuilder<S, &mut HostEvmEnv<D, H, C>> {
            CallBuilder::new(self.env, self.address, call)
        }
    }

    impl<'a, S, T, N, P, H, C> CallBuilder<S, &'a mut HostEvmEnv<AlloyDb<T, N, P>, H, C>>
    where
        T: Transport + Clone,
        N: Network,
        P: Provider<T, N> + Send + 'static,
        S: SolCall + Send + 'static,
        <S as SolCall>::Return: Send,
        H: EvmBlockHeader + Clone + Send + 'static,
    {
        /// Fetches all the EIP-1186 storage proofs from the `access_list`. This can help to
        /// drastically reduce the number of RPC calls required during execution, as
        /// `eth_getStorageAt` calls are then only required for storage accesses not included in the
        /// list. This does *not* set the access list as part of the transaction (as specified in
        /// EIP-2930), and thus can only be specified during preflight on the host.
        pub async fn prefetch_access_list(self, access_list: AccessList) -> Result<Self> {
            let db = self.env.db_mut();
            db.add_access_list(access_list).await?;

            Ok(self)
        }

        /// Executes the call using an [EvmEnv] constructed with [Contract::preflight].
        ///
        /// This uses [tokio::task::spawn_blocking] to run the blocking revm execution.
        ///
        /// [EvmEnv]: crate::EvmEnv
        pub async fn call(self) -> Result<S::Return> {
            log::info!(
                "Executing preflight calling '{}' on {}",
                S::SIGNATURE,
                self.tx.to
            );

            // as mutable references are not possible, the DB must be moved in and out of the task
            let db = self.env.db.take().unwrap();

            let cfg = self.env.cfg_env.clone();
            let header = self.env.header.inner().clone();
            let (result, db) = tokio::task::spawn_blocking(move || {
                let mut evm = new_evm(db, cfg, header);
                let result = self.tx.transact(&mut evm);
                let (db, _) = evm.into_db_and_env_with_handler_cfg();

                (result, db)
            })
            .await
            .expect("EVM execution panicked");

            // restore the DB before handling errors, so that we never return an env without a DB
            self.env.db = Some(db);

            result.map_err(|err| anyhow!("call '{}' failed: {}", S::SIGNATURE, err))
        }

        /// Automatically prefetches the access list before executing the call using an [EvmEnv]
        /// constructed with [Contract::preflight].
        ///
        /// This is equivalent to calling [CallBuilder::prefetch_access_list] with the EIP-2930
        /// access list as returned by the corresponding `eth_createAccessList` RPC and
        /// [CallBuilder::call]. See the corresponding methods for more information.
        ///
        /// [EvmEnv]: crate::EvmEnv
        pub async fn call_with_prefetch(self) -> Result<S::Return> {
            let access_list = {
                let tx = <N as Network>::TransactionRequest::default()
                    .with_from(self.tx.caller)
                    .with_gas_limit(self.tx.gas_limit)
                    .with_gas_price(self.tx.gas_price.to())
                    .with_to(self.tx.to)
                    .with_value(self.tx.value)
                    .with_input(self.tx.data.clone());

                let db = self.env.db_mut();
                let provider = db.inner().provider();
                let access_list = provider
                    .create_access_list(&tx)
                    .hash(db.inner().block_hash())
                    .await
                    .context("eth_createAccessList failed")?;
                access_list.access_list
            };

            self.prefetch_access_list(access_list)
                .await
                .context("prefetching access list failed")?
                .call()
                .await
        }
    }
}

impl<'a, S, H> CallBuilder<S, &'a GuestEvmEnv<H>>
where
    S: SolCall,
    H: EvmBlockHeader,
{
    /// Executes the call and returns an error if the call fails.
    ///
    /// In general, it's recommended to use [CallBuilder::call] unless explicit error handling is
    /// required.
    pub fn try_call(self) -> Result<S::Return, String> {
        let mut evm = new_evm::<_, H>(
            WrapStateDb::new(self.env.db()),
            self.env.cfg_env.clone(),
            self.env.header.inner(),
        );
        self.tx.transact(&mut evm)
    }

    /// Executes the call and panics on failure.
    ///
    /// A convenience wrapper for [CallBuilder::try_call], panicking if the call fails. Useful when
    /// success is expected.
    pub fn call(self) -> S::Return {
        self.try_call().unwrap()
    }
}

/// Transaction data to be used with [CallBuilder] for an execution.
#[derive(Debug, Clone)]
struct CallTxData<S> {
    caller: Address,
    gas_limit: u64,
    gas_price: U256,
    to: Address,
    value: U256,
    data: Vec<u8>,
    phantom: PhantomData<S>,
}

impl<S: SolCall> CallTxData<S> {
    /// Compile-time assertion that the call C has a return value.
    const RETURNS: () = assert!(
        mem::size_of::<S::Return>() > 0,
        "Function call must have a return value"
    );

    /// Executes the call in the provided [Evm].
    fn transact<EXT, DB>(self, evm: &mut Evm<'_, EXT, DB>) -> Result<S::Return, String>
    where
        DB: Database,
        <DB as Database>::Error: std::error::Error + Send + Sync + 'static,
    {
        #[allow(clippy::let_unit_value)]
        let _ = Self::RETURNS;

        let tx_env = evm.tx_mut();
        tx_env.caller = self.caller;
        tx_env.gas_limit = self.gas_limit;
        tx_env.gas_price = self.gas_price;
        tx_env.transact_to = TxKind::Call(self.to);
        tx_env.value = self.value;
        tx_env.data = self.data.into();

        let ResultAndState { result, .. } = evm
            .transact_preverified()
            .map_err(|err| format!("EVM error: {:#}", anyhow!(err)))?;
        let output = match result {
            ExecutionResult::Success { reason, output, .. } => {
                // there must be a return value to decode
                if reason != SuccessReason::Return {
                    Err(format!("did not return: {:?}", reason))
                } else {
                    Ok(output)
                }
            }
            ExecutionResult::Revert { output, .. } => Err(format!("reverted: {}", output)),
            ExecutionResult::Halt { reason, .. } => Err(format!("halted: {:?}", reason)),
        }?;
        let returns = S::abi_decode_returns(&output.into_data(), true).map_err(|err| {
            format!(
                "return type invalid; expected '{}': {}",
                <S::ReturnTuple<'_> as SolType>::SOL_NAME,
                err
            )
        })?;

        Ok(returns)
    }
}

fn new_evm<'a, D, H>(db: D, cfg: CfgEnvWithHandlerCfg, header: impl Borrow<H>) -> Evm<'a, (), D>
where
    D: Database,
    H: EvmBlockHeader,
{
    Evm::builder()
        .with_db(db)
        .with_cfg_env_with_handler_cfg(cfg)
        .modify_block_env(|blk_env| header.borrow().fill_block_env(blk_env))
        .build()
}
