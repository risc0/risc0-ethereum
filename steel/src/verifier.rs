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

use crate::history::beacon_roots::BeaconRootsContract;
use crate::state::WrapStateDb;
use crate::{Commitment, EvmBlockHeader, GuestEvmEnv};
use alloy_primitives::U256;

/// ### Examples
/// ```rust,no_run
/// # use risc0_steel::{ethereum::EthEvmEnv, Contract, host::BlockNumberOrTag};
/// # use alloy_primitives::address;
/// # use alloy_sol_types::sol;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// use url::Url;
/// use risc0_steel::Verifier;
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
/// let url: Url = "https://ethereum-rpc.publicnode.com".parse()?;
/// let mut env = EthEvmEnv::builder().rpc(url.clone()).block_number_or_tag(BlockNumberOrTag::Parent).build().await?;
/// let mut contract = Contract::preflight(contract_address, &mut env);
/// contract.call_builder(&get_balance).call().await?;
///
/// let evm_input = env.into_input().await?;
///
///
/// // Guest:
/// let evm_env = evm_input.into_env();
/// let contract = Contract::new(contract_address, &evm_env);
/// contract.call_builder(&get_balance).call();
///
/// let mut env2 = EthEvmEnv::builder().rpc(url).build().await?;
/// Verifier::preflight(&mut env2).verify(evm_env.commitment())?;
///
/// # Ok(())
/// # }
/// ```
///
/// [EthEvmEnv::builder]: crate::ethereum::EthEvmEnv::builder
/// [EvmEnv::builder]: crate::EvmEnv::builder
/// [EvmInput::into_env]: crate::EvmInput::into_env
pub struct Verifier<E> {
    env: E,
}

impl<'a, H: EvmBlockHeader> Verifier<&'a GuestEvmEnv<H>> {
    pub fn new(env: &'a GuestEvmEnv<H>) -> Self {
        Self { env }
    }

    pub fn verify(&self, commitment: &Commitment) {
        let (id, version) = commitment.decode_id();
        match version {
            0 => {
                let Some(block_number) = block_hash(self.env.header().inner(), id) else {
                    panic!()
                };
                let db = self.env.db();
                assert_eq!(db.block_hash(block_number), commitment.digest);
            }
            1 => {
                let db = WrapStateDb::new(self.env.db());
                let beacon_root = BeaconRootsContract::get_from_db(db, id).unwrap();
                assert_eq!(beacon_root, commitment.digest);
            }
            _ => {
                unimplemented!()
            }
        }
    }
}

fn block_hash(header: &impl EvmBlockHeader, calldata: U256) -> Option<u64> {
    let requested_number: u64 = calldata.saturating_to();
    let diff = header.number().saturating_sub(requested_number);
    (diff > 0 && diff <= 256).then_some(requested_number)
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::history::beacon_roots;
    use crate::host::HostEvmEnv;
    use anyhow::ensure;
    use revm::Database;

    impl<'a, D: Database, H: EvmBlockHeader, C> Verifier<&'a mut HostEvmEnv<D, H, C>>
    where
        beacon_roots::Error: From<<D as Database>::Error>,
        anyhow::Error: From<<D as Database>::Error>,
    {
        pub fn preflight(env: &'a mut HostEvmEnv<D, H, C>) -> Self {
            Self { env }
        }

        pub fn verify(&mut self, commitment: &Commitment) -> anyhow::Result<()> {
            let (id, version) = commitment.decode_id();
            match version {
                0 => {
                    let Some(block_number) = block_hash(self.env.header().inner(), id) else {
                        panic!()
                    };
                    let db = self.env.db_mut();
                    ensure!(db.block_hash(block_number)? == commitment.digest);

                    Ok(())
                }
                1 => {
                    let beacon_root = BeaconRootsContract::get_from_db(self.env.db_mut(), id)?;
                    ensure!(beacon_root == commitment.digest);

                    Ok(())
                }
                _ => {
                    unimplemented!()
                }
            }
        }
    }
}
