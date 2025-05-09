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

//! Types related to account queries.
use crate::{EvmFactory, GuestEvmEnv, StateAccount};
use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::Result;

/// Information about an Ethereum account.
///
/// This struct contains all the essential data that makes up an Ethereum account's state,
/// including its balance, nonce, storage, and code information.
#[derive(Debug, Clone, Eq)]
pub struct AccountInfo {
    /// The number of transactions sent from this account (also used as replay protection).
    pub nonce: u64,
    /// The account's current balance in Wei.
    pub balance: U256,
    /// The Keccak-256 hash of the root node of the account's storage trie.
    pub storage_root: B256,
    /// The Keccak-256 hash of the account's code.
    /// For non-contract accounts (EOAs), this will be the hash of empty bytes.
    pub code_hash: B256,
    /// The actual bytecode of the account.
    /// This is `None` when the code hasn't been loaded.
    pub code: Option<Bytes>,
}

impl PartialEq for AccountInfo {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.balance == other.balance
            && self.storage_root == other.storage_root
            && self.code_hash == other.code_hash
    }
}

impl From<StateAccount> for AccountInfo {
    fn from(account: StateAccount) -> Self {
        Self {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: account.storage_root,
            code_hash: account.code_hash,
            code: None,
        }
    }
}

/// Represents an EVM account query.
///
/// ### Usage
/// - **Preflight calls on the Host:** To prepare the account query on the host environment and
///   build the necessary proof, use [Account::preflight].
/// - **Calls in the Guest:** To initialize the account query in the guest, use [Account::new].
///
/// ### Examples
/// ```rust,no_run
/// # use risc0_steel::{Account, ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv}};
/// # use alloy_primitives::address;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// let account_address = address!("F977814e90dA44bFA03b6295A0616a897441aceC");
///
/// // Host:
/// let url = "https://ethereum-rpc.publicnode.com".parse()?;
/// let mut env = EthEvmEnv::builder().rpc(url).chain_spec(&ETH_MAINNET_CHAIN_SPEC).build().await?;
/// let account = Account::preflight(account_address, &mut env);
/// let info = account.bytecode(true).info().await?;
///
/// let evm_input = env.into_input().await?;
///
/// // Guest:
/// let env = evm_input.into_env(&ETH_MAINNET_CHAIN_SPEC);
/// let account = Account::new(account_address, &env);
/// let info = account.bytecode(true).info();
///
/// # Ok(())
/// # }
/// ```
pub struct Account<E> {
    address: Address,
    env: E,
    code: bool,
}

impl<E> Account<E> {
    /// Sets whether to fetch the bytecode for this account.
    ///
    /// If set to `true`, the bytecode will be fetched when calling [Account::info].
    pub fn bytecode(mut self, code: bool) -> Self {
        self.code = code;
        self
    }
}

impl<'a, F: EvmFactory> Account<&'a GuestEvmEnv<F>> {
    /// Constructor for querying an Ethereum account in the guest.
    pub fn new(address: Address, env: &'a GuestEvmEnv<F>) -> Self {
        Self {
            address,
            env,
            code: false,
        }
    }

    /// Attempts to get the [AccountInfo] for the corresponding account and returns an error if the
    /// query fails.
    ///
    /// In general, it's recommended to use [Account::info] unless explicit error handling is
    /// required.
    pub fn try_info(self) -> Result<AccountInfo> {
        let db = self.env.db();
        let account = db.account(self.address).unwrap_or_default();
        let mut info = AccountInfo::from(account);
        if self.code && info.code.is_none() {
            let code = db.code_by_hash(info.code_hash);
            info.code = Some(code.clone());
        }

        Ok(info)
    }

    /// Gets the [AccountInfo] for the corresponding account and panics on failure.
    ///
    /// A convenience wrapper for [Account::try_info], panicking if the query fails. Useful when
    /// success is expected.
    pub fn info(self) -> AccountInfo {
        self.try_info().unwrap()
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::host::{db::ProviderDb, HostEvmEnv};
    use alloy::{network::Network, providers::Provider};
    use anyhow::{ensure, Context};
    use revm::Database as RevmDatabase;

    impl<'a, N, P, F, C> Account<&'a mut HostEvmEnv<ProviderDb<N, P>, F, C>>
    where
        N: Network,
        P: Provider<N>,
        ProviderDb<N, P>: Send + 'static,
        F: EvmFactory,
    {
        /// Constructor for preflighting queries to an Ethereum account on the host.
        ///
        /// Initializes the environment for querying account information, fetching necessary data
        /// via the [Provider], and generating a storage proof for any accessed elements using
        /// [EvmEnv::into_input].
        ///
        /// [EvmEnv::into_input]: crate::EvmEnv::into_input
        /// [EvmEnv]: crate::EvmEnv
        pub fn preflight(
            address: Address,
            env: &'a mut HostEvmEnv<ProviderDb<N, P>, F, C>,
        ) -> Self {
            Self {
                address,
                env,
                code: false,
            }
        }

        /// Gets the [AccountInfo] for the corresponding account using an [EvmEnv] constructed with
        /// [Account::preflight].
        ///
        /// [EvmEnv]: crate::EvmEnv
        pub async fn info(self) -> Result<AccountInfo> {
            log::info!("Executing preflight querying account {}", &self.address);

            let account = self
                .env
                .db_mut()
                .state_account(self.address)
                .await
                .context("failed to get state account information")?;
            let mut info = AccountInfo::from(account);
            if self.code && info.code.is_none() {
                // basic must always be called first
                let basic = self
                    .env
                    .spawn_with_db(move |db| db.basic(self.address))
                    .await
                    .context("failed to get basic account information")?
                    .unwrap_or_default();
                ensure!(basic.code_hash == account.code_hash, "code_hash mismatch");

                let code = self
                    .env
                    .spawn_with_db(move |db| db.code_by_hash(info.code_hash))
                    .await
                    .context("failed to get account code by its hash")?;
                info.code = Some(code.original_bytes());
            }

            Ok(info)
        }
    }
}
