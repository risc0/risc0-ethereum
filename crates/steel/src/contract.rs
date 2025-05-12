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

use crate::{state::WrapStateDb, EvmFactory, GuestEvmEnv};
use alloy_evm::Evm;
use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolType};
use anyhow::anyhow;
use revm::context::result::{ExecutionResult, ResultAndState, SuccessReason};
use std::{fmt::Debug, marker::PhantomData};

/// Represents a contract instance for interacting with EVM environments.
///
/// This struct provides a way to interact with a deployed smart contract
/// at a specific `address` within a given EVM environment `E`.
///
/// **Note:** This contract interaction is not type-safe regarding the ABI.
/// Ensure the deployed contract at `address` matches the ABI used for calls (`S: SolCall`).
///
/// ### Usage Scenarios
///
/// 1. **Host (Preflight):** Use [Contract::preflight] to set up calls on the host environment. The
///    environment can be initialized using the [EthEvmEnv::builder] or [EvmEnv::builder]. This
///    fetches necessary state and prepares proofs for guest execution.
///     - Consider [CallBuilder::call_with_prefetch] for calls with many storage accesses to
///       potentially optimize preflight time by reducing RPC calls.
/// 2. **Guest:** Use [Contract::new] within the guest environment, typically initialized from
///    [EvmInput::into_env].
///
///
/// ### Making Contract Calls (Host Preflight or Guest Execution)
///
/// To interact with the contract's functions, you use the [Contract::call_builder] method to
/// prepare a call.
/// This follows a specific workflow:
///
/// 1. **Create Builder:** Call [Contract::call_builder] with a specific Solidity function call
///    object (e.g., `MyCall { arg1: ..., arg2: ... }` derived using `alloy_sol_types::sol!`). This
///    returns a [CallBuilder] instance, initializing its internal transaction environment (`tx`)
///    with the contract address and call data.
///
/// 2.  **Configure Transaction:** Because the underlying transaction type (`EvmFactory::Tx`) is
///     generic, configuration parameters (like caller address, value, gas limit, nonce)
///     are set by **directly modifying the public `.tx` field** of the returned [CallBuilder]
///     instance.
///     ```rust,no_run
///     # use risc0_steel::{ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}, Contract};
///     # use alloy_primitives::{Address, U256};
///     # use alloy_sol_types::sol;
///     # sol! { interface Test { function test() external view returns (uint); } }
///     # #[tokio::main(flavor = "current_thread")]
///     # async fn main() -> anyhow::Result<()> {
///     # let rpc_url = "https://ethereum-rpc.publicnode.com".parse()?;
///     # let mut env = EthEvmEnv::builder().rpc(rpc_url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
///     # let mut contract = Contract::preflight(Address::ZERO, &mut env);
///     # let my_call = Test::testCall {};
///     let mut builder = contract.call_builder(&my_call);
///     builder.tx.caller = Address::ZERO;
///     builder.tx.value = U256::from(0); // Set value if payable
///     builder.tx.gas_limit = 100_000;
///     // ... set other fields like gas_price, nonce as needed
///     # Ok(())
///     # }
///     ```
///     **Note:** Fluent configuration methods like `.from(address)` or `.value(amount)` are
///     **not available** directly on the `CallBuilder` due to this generic design. You must
///     use direct field access on `.tx`. Consult the documentation of the specific `Tx`
///     type provided by your chosen [`EvmFactory`] for available fields (e.g., `revm::primitives::TxEnv`).
///
/// 3. **Execute Call:** Once configured, execute the call using the appropriate method on the
///    [`CallBuilder`] instance. Common methods include:
///     - `.call()`: Executes in the guest, panicking on EVM errors.
///     - `.try_call()`: Executes in the guest, returning a `Result` for error handling.
///     - `.call().await`: Executes preflight on the host (requires `host` feature).
///     - `.call_with_prefetch().await`: Executes preflight on the host, potentially optimizing
///       state loading (requires `host` feature).
///
/// See the [`CallBuilder`] documentation for more details on execution methods.
///
/// ### Examples
///
/// ```rust,no_run
/// # use risc0_steel::{ethereum::{EthEvmInput, EthEvmEnv, ETH_MAINNET_CHAIN_SPEC}, Contract, host::BlockNumberOrTag};
/// # use alloy_primitives::{Address, address};
/// # use alloy_sol_types::sol;
/// # use url::Url;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
///  const CONTRACT_ADDRESS: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7"); // USDT
///  const ACCOUNT_TO_QUERY: Address = address!("F977814e90dA44bFA03b6295A0616a897441aceC"); // Binance
///  sol! {
///     interface IERC20 {
///         function balanceOf(address account) external view returns (uint);
///     }
/// }
/// const CALL: IERC20::balanceOfCall = IERC20::balanceOfCall { account: ACCOUNT_TO_QUERY };
///
/// // === Host Setup ===
/// let rpc_url = "https://ethereum-rpc.publicnode.com".parse()?;
/// let mut host_env = EthEvmEnv::builder().rpc(rpc_url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
///
/// // Preflight the call on the host
/// let mut contract_host = Contract::preflight(CONTRACT_ADDRESS, &mut host_env);
/// let mut builder = contract_host.call_builder(&CALL);
/// // Configure via builder.tx
/// builder.tx.caller = Address::default();
/// builder.tx.gas_limit = 10_000;
/// // Execute
/// let balance_result = builder.call().await?;
/// println!("Host preflight balance: {}", balance_result);
///
/// // Generate input for the guest
/// let evm_input = host_env.into_input().await?;
///
/// // === Guest Setup & Execution ===
/// // (Inside the RISC Zero guest)
/// # {
/// let guest_env = evm_input.into_env(&ETH_MAINNET_CHAIN_SPEC);
/// let contract_guest = Contract::new(CONTRACT_ADDRESS, &guest_env);
///
/// // Execute the same call in the guest
/// let mut builder = contract_guest.call_builder(&CALL);
/// builder.tx.caller = Address::default();
/// builder.tx.gas_limit = 10_000;
/// let guest_balance_result = builder.call();
/// println!("Guest execution balance: {}", guest_balance_result);
/// # }
/// # Ok(())
/// # }
/// ```
///
/// [EthEvmEnv::builder]: crate::ethereum::EthEvmEnv
/// [EvmEnv::builder]: crate::EvmEnv
/// [EvmInput::into_env]: crate::EvmInput::into_env
pub struct Contract<E> {
    address: Address,
    env: E,
}

impl<'a, F: EvmFactory> Contract<&'a GuestEvmEnv<F>> {
    /// Creates a `Contract` instance for use within the guest environment.
    ///
    /// The `env` should typically be obtained via [EvmInput::into_env].
    ///
    /// [EvmInput::into_env]: crate::EvmInput::into_env
    pub fn new(address: Address, env: &'a GuestEvmEnv<F>) -> Self {
        Self { address, env }
    }

    /// Initializes a builder for executing a specific contract call (`S`) in the guest.
    pub fn call_builder<S: SolCall>(&self, call: &S) -> CallBuilder<F::Tx, S, &GuestEvmEnv<F>> {
        CallBuilder::new(F::new_tx(self.address, call.abi_encode().into()), self.env)
    }
}

/// Represents a prepared EVM contract call, ready for configuration and execution.
///
/// Instances are created via [Contract::call_builder]. The primary interaction
/// involves configuring the transaction parameters via the public [CallBuilder::tx] field,
/// followed by invoking an execution method like `.call()`.
///
/// See the documentation on the [Contract] struct for a detailed explanation of the
/// configuration workflow and examples.
#[derive(Debug, Clone)]
#[must_use = "CallBuilder does nothing unless an execution method like `.call()` is called"]
pub struct CallBuilder<T, S, E> {
    /// The transaction environment (`EvmFactory::Tx`) containing call parameters.
    ///
    /// **Configuration:** This field holds the transaction details (caller, value, gas, etc.).
    /// It **must be configured directly** by modifying its members *before* calling an
    /// execution method.
    ///
    /// Example: `builder.tx.caller = MY_ADDRESS; builder.tx.gas_limit = 100_000;`
    pub tx: T,
    /// The EVM environment (either host or guest).
    env: E,
    /// Phantom data for the `SolCall` type `S`.
    phantom: PhantomData<S>,
}

impl<T, S: SolCall, E> CallBuilder<T, S, E> {
    /// Compile-time assertion that the call has a return value.
    const RETURNS: () = assert!(
        std::mem::size_of::<S::Return>() > 0,
        "Function call must have a return value"
    );

    fn new(tx: T, env: E) -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = Self::RETURNS;

        Self {
            tx,
            env,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::{
        ethereum::EthEvmFactory,
        host::{db::ProviderDb, HostEvmEnv},
    };
    use alloy::{
        eips::eip2930::AccessList,
        network::{Ethereum, Network, TransactionBuilder},
        providers::Provider,
    };
    use anyhow::{anyhow, Context, Result};

    impl<'a, F, D, C> Contract<&'a mut HostEvmEnv<D, F, C>>
    where
        F: EvmFactory,
    {
        /// Creates a `Contract` instance for use on the host for preflighting calls.
        ///
        /// This prepares the environment for simulating the call, fetching necessary
        /// state via the `Provider` within `env`, and enabling proof generation
        /// via [HostEvmEnv::into_input].
        pub fn preflight(address: Address, env: &'a mut HostEvmEnv<D, F, C>) -> Self {
            Self { address, env }
        }

        /// Initializes a builder for preflighting a specific contract call (`S`) on the host.
        pub fn call_builder<S: SolCall>(
            &mut self,
            call: &S,
        ) -> CallBuilder<F::Tx, S, &mut HostEvmEnv<D, F, C>> {
            CallBuilder::new(F::new_tx(self.address, call.abi_encode().into()), self.env)
        }
    }

    // Methods applicable when using ProviderDb on the host
    impl<S, F, N, P, C> CallBuilder<F::Tx, S, &mut HostEvmEnv<ProviderDb<N, P>, F, C>>
    where
        N: Network,
        P: Provider<N> + Send + Sync + 'static,
        S: SolCall + Send + Sync + 'static,
        <S as SolCall>::Return: Send,
        F: EvmFactory,
    {
        /// Prefetches state for a given EIP-2930 `AccessList` on the host.
        ///
        /// Fetches EIP-1186 storage proofs for the items
        /// in the `access_list`. This can reduce the number of individual RPC calls
        /// (`eth_getStorageAt`) needed during subsequent execution simulation if the
        /// accessed slots are known beforehand.
        ///
        /// This method *only* fetches data; it does *not* set the access list field
        /// on the transaction itself (EIP-2930).
        ///
        /// ### Usage
        /// Useful when an access list is already available. For automatic generation
        /// and prefetching, see [`CallBuilder::call_with_prefetch`].
        ///
        /// ### Example
        /// ```rust,no_run
        /// # use risc0_steel::{ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}, Contract};
        /// # use alloy_primitives::address;
        /// # use alloy_sol_types::sol;
        /// # use alloy::eips::eip2930::AccessList;
        /// # use url::Url;
        /// # sol! { interface Test { function test() external view returns (uint); } }
        /// # #[tokio::main(flavor = "current_thread")]
        /// # async fn main() -> anyhow::Result<()> {
        /// # let rpc_url = "https://ethereum-rpc.publicnode.com".parse()?;
        /// # let mut env = EthEvmEnv::builder().rpc(rpc_url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
        /// # let contract_address = address!("0x0000000000000000000000000000000000000000");
        /// # let call = Test::testCall {};
        /// # let access_list = AccessList::default();
        /// let mut contract = Contract::preflight(contract_address, &mut env);
        /// let builder = contract.call_builder(&call).prefetch_access_list(access_list).await?;
        /// let result = builder.call().await?;
        /// # Ok(())
        /// # }
        /// ```
        pub async fn prefetch_access_list(self, access_list: AccessList) -> Result<Self> {
            let db = self.env.db_mut();
            db.add_access_list(access_list).await?;

            Ok(self)
        }

        /// Executes the configured call during host preflight.
        ///
        /// This simulates the transaction execution using `revm` within a blocking thread
        /// (via [`tokio::task::spawn_blocking`]) to avoid blocking the async runtime.
        /// It uses the state fetched (and potentially prefetched) into the `ProviderDb`.
        ///
        /// Returns the decoded return value of the call or an error if execution fails.
        pub async fn call(self) -> Result<S::Return> {
            log::info!("Executing preflight calling '{}'", S::SIGNATURE);

            // as mutable references are not possible, the DB must be moved in and out of the task
            let mut db = self.env.db.take().unwrap();

            let chain_id = self.env.chain_id;
            let spec = self.env.spec;
            let header = self.env.header.inner().clone();
            let (result, db) = tokio::task::spawn_blocking(move || {
                let exec_result = {
                    let mut evm = F::create_evm(&mut db, chain_id, spec, &header);
                    transact::<_, F, S>(self.tx, &mut evm)
                };
                (exec_result, db)
            })
            .await
            .expect("EVM execution panicked");

            // restore the DB before handling errors, so that we never return an env without a DB
            self.env.db = Some(db);

            result.map_err(|err| anyhow!("call '{}' failed: {}", S::SIGNATURE, err))
        }
    }

    // Methods specific to Ethereum network + EthEvmFactory (e.g., eth_createAccessList)
    impl<S, P, C>
        CallBuilder<
            <EthEvmFactory as EvmFactory>::Tx,
            S,
            &mut HostEvmEnv<ProviderDb<Ethereum, P>, EthEvmFactory, C>,
        >
    where
        S: SolCall + Send + Sync + 'static,
        <S as SolCall>::Return: Send,
        P: Provider<Ethereum> + Send + Sync + 'static,
    {
        /// Automatically creates and prefetches an EIP-2930 access list, then executes the call.
        ///
        /// This method aims to optimize host preflight time for calls involving numerous
        /// storage reads (`SLOAD`). It performs the following steps:
        /// 1. Calls `eth_createAccessList` RPC to determine the storage slots and accounts the
        ///    transaction is likely to access.
        /// 2. Calls [CallBuilder::prefetch_access_list] with the generated list to fetch the
        ///    required state efficiently (often in a single batch RPC).
        /// 3. Executes the call simulation using [CallBuilder::call].
        ///
        /// ### Trade-offs
        /// - **Node Compatibility:** Relies on the `eth_createAccessList` RPC, which might not be
        ///   available or fully supported on all Ethereum node software or chains.
        /// - **Gas Estimation Issues:** Some node implementations might perform gas checks or
        ///   require sufficient balance in the `from` account for `eth_createAccessList`, even for
        ///   view calls. Setting a relevant `from` address  might be necessary.
        ///
        /// ### Example
        /// ```rust,no_run
        /// # use risc0_steel::{ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}, Contract};
        /// # use alloy_primitives::address;
        /// # use alloy_sol_types::sol;
        /// # use url::Url;
        /// # sol! { interface Test { function test() external view returns (uint); } }
        /// # #[tokio::main(flavor = "current_thread")]
        /// # async fn main() -> anyhow::Result<()> {
        /// # let rpc_url = "https://ethereum-rpc.publicnode.com".parse()?;
        /// # let mut env = EthEvmEnv::builder().rpc(rpc_url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
        /// # let contract_address = address!("0x0000000000000000000000000000000000000000");
        /// # let call = Test::testCall {};
        /// let mut contract = Contract::preflight(contract_address, &mut env);
        /// // Automatically generates access list, fetches state, and executes
        /// let result = contract.call_builder(&call).call_with_prefetch().await?;
        /// # Ok(())
        /// # }
        /// ```
        pub async fn call_with_prefetch(self) -> Result<S::Return> {
            let access_list = {
                let tx_request = <Ethereum as Network>::TransactionRequest::default()
                    .with_from(self.tx.caller)
                    .with_gas_limit(self.tx.gas_limit)
                    .with_gas_price(self.tx.gas_price)
                    .with_kind(self.tx.kind)
                    .with_value(self.tx.value)
                    .with_input(self.tx.data.clone());

                let db = self.env.db_mut();
                let provider = db.inner().provider();
                let hash = db.inner().block();

                let access_list_result = provider
                    .create_access_list(&tx_request)
                    .hash(hash)
                    .await
                    .context("eth_createAccessList failed")?;

                access_list_result.access_list
            };

            // Add the generated access list to the DB for prefetching
            self.env
                .db_mut()
                .add_access_list(access_list)
                .await
                .context("failed to add generated access list")?;

            self.call().await
        }
    }
}

impl<S, F> CallBuilder<F::Tx, S, &GuestEvmEnv<F>>
where
    S: SolCall,
    F: EvmFactory,
{
    /// Executes the call within the guest environment, returning a `Result`.
    ///
    /// Use this if you need to handle potential EVM execution errors explicitly
    /// (e.g., reverts, halts) within the guest. The error type is `String` for simplicity
    /// in the guest context.
    ///
    /// For straightforward calls where failure should halt guest execution, prefer
    /// [CallBuilder::call].
    pub fn try_call(self) -> Result<S::Return, String> {
        // create a temporary EVM instance for this call
        let mut evm = F::create_evm(
            // wrap the database and header for guest state access
            WrapStateDb::new(self.env.db(), &self.env.header),
            self.env.chain_id,
            self.env.spec,
            self.env.header.inner(),
        );
        // execute the transaction
        transact::<_, F, S>(self.tx, &mut evm)
    }

    /// Executes the call within the guest environment, panicking on failure.
    ///
    /// This is a convenience wrapper around [CallBuilder::try_call]. It unwraps
    /// the result, causing the guest to panic if the EVM call reverts, halts, or
    /// encounters an error. Use this when a successful call is expected.
    #[track_caller] // Improve panic message location
    pub fn call(self) -> S::Return {
        match self.try_call() {
            Ok(value) => value,
            Err(e) => panic!("Executing call '{}' failed: {}", S::SIGNATURE, e),
        }
    }
}

/// Executes a transaction using the provided EVM instance and decodes the result.
/// Returns `Result<S::Return, String>` where `String` contains the error reason.
fn transact<DB, F, S>(tx: F::Tx, evm: &mut F::Evm<DB>) -> Result<S::Return, String>
where
    DB: alloy_evm::Database,
    F: EvmFactory,
    S: SolCall,
{
    let ResultAndState { result, .. } = evm
        .transact_raw(tx)
        .map_err(|err| format!("EVM error: {:#}", anyhow!(err)))?;
    let output_bytes = match result {
        ExecutionResult::Success { reason, output, .. } => {
            // ensure the transaction returned, not stopped or other success reason
            if reason == SuccessReason::Return {
                Ok(output)
            } else {
                Err(format!(
                    "succeeded but did not return (reason: {:?})",
                    reason
                ))
            }
        }
        ExecutionResult::Revert { output, .. } => Err(format!("reverted with output: {}", output)),
        ExecutionResult::Halt { reason, .. } => Err(format!("halted: {:?}", reason)),
    }?;

    // decode the successful return output
    S::abi_decode_returns(&output_bytes.into_data()).map_err(|err| {
        format!(
            "Failed to decode return data, expected type '{}': {}",
            <S::ReturnTuple<'_> as SolType>::SOL_NAME,
            err
        )
    })
}
