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
pub use revm::primitives::{AccountInfo, Bytecode};

use crate::{state::WrapStateDb, EvmBlockHeader, GuestEvmEnv};
use alloy_primitives::Address;
use anyhow::Result;
use revm::Database as RevmDatabase;

/// Represents an EVM account query.
///
/// ### Usage
/// - **Preflight calls on the Host:** To prepare the account query on the host environment and
///   build the necessary proof, use [Account::preflight].
/// - **Calls in the Guest:** To initialize the account query in the guest, use [Account::new].
///
/// ### Examples
/// ```rust,no_run
/// # use risc0_steel::{Account, ethereum::EthEvmEnv};
/// # use alloy_primitives::address;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// let account_address = address!("F977814e90dA44bFA03b6295A0616a897441aceC");
///
/// // Host:
/// let url = "https://ethereum-rpc.publicnode.com".parse()?;
/// let mut env = EthEvmEnv::builder().rpc(url).build().await?;
/// let account = Account::preflight(account_address, &mut env);
/// let info = account.bytecode(true).info().await?;
///
/// let evm_input = env.into_input().await?;
///
/// // Guest:
/// let env = evm_input.into_env();
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

impl<'a, H: EvmBlockHeader> Account<&'a GuestEvmEnv<H>> {
    /// Constructor for querying an Ethereum account in the guest.
    pub fn new(address: Address, env: &'a GuestEvmEnv<H>) -> Self {
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
        let mut db = WrapStateDb::new(self.env.db());
        let mut info = db.basic(self.address)?.unwrap_or_default();
        if self.code && info.code.is_none() {
            let code = db.code_by_hash(info.code_hash)?;
            info.code = Some(code);
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
    use crate::host::HostEvmEnv;
    use anyhow::Context;
    use std::error::Error as StdError;

    impl<'a, D, H, C> Account<&'a mut HostEvmEnv<D, H, C>>
    where
        D: RevmDatabase + Send + 'static,
        <D as RevmDatabase>::Error: StdError + Send + Sync + 'static,
    {
        /// Constructor for preflighting queries to an Ethereum account on the host.
        ///
        /// Initializes the environment for querying account information, fetching necessary data
        /// via the [Provider], and generating a storage proof for any accessed elements using
        /// [EvmEnv::into_input].
        ///
        /// [EvmEnv::into_input]: crate::EvmEnv::into_input
        /// [EvmEnv]: crate::EvmEnv
        /// [Provider]: alloy::providers::Provider
        pub fn preflight(address: Address, env: &'a mut HostEvmEnv<D, H, C>) -> Self {
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

            let mut info = self
                .env
                .spawn_with_db(move |db| db.basic(self.address))
                .await
                .context("failed to get basic account information")?
                .unwrap_or_default();
            if self.code && info.code.is_none() {
                let code = self
                    .env
                    .spawn_with_db(move |db| db.code_by_hash(info.code_hash))
                    .await
                    .context("failed to get account code by its hash")?;
                info.code = Some(code);
            }

            Ok(info)
        }
    }
}
