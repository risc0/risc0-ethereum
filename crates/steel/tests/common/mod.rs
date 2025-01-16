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

use std::{fmt::Debug, sync::LazyLock};

use alloy::{
    eips::eip2930::AccessList, network::Ethereum, providers::Provider, transports::Transport,
};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use revm::primitives::SpecId;
use risc0_steel::{config::ChainSpec, ethereum::EthEvmEnv, CallBuilder, Contract};

pub static ANVIL_CHAIN_SPEC: LazyLock<ChainSpec> =
    LazyLock::new(|| ChainSpec::new_single(31337, SpecId::CANCUN));

/// Executes a new [SolCall] using steel.
pub async fn eth_call<T, P, C>(
    provider: P,
    address: Address,
    call: C,
    options: CallOptions,
) -> C::Return
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + 'static,
    C: SolCall + Send + 'static,
    C::Return: PartialEq + Debug + Send,
{
    let mut env = EthEvmEnv::builder()
        .provider(provider)
        .build()
        .await
        .unwrap()
        .with_chain_spec(&ANVIL_CHAIN_SPEC);
    let block_hash = env.header().seal();
    let block_number = env.header().number;

    let preflight_result = {
        let mut preflight = Contract::preflight(address, &mut env);
        let mut builder = preflight.call_builder(&call);
        if let Some(access_list) = options.access_list.clone() {
            builder = builder.prefetch_access_list(access_list).await.unwrap();
        }
        options.apply(builder).call().await.unwrap()
    };

    let input = env.into_input().await.unwrap();
    let env = input.into_env().with_chain_spec(&ANVIL_CHAIN_SPEC);

    let commitment = env.commitment();
    assert_eq!(commitment.digest, block_hash, "invalid commitment");
    assert_eq!(
        commitment.id,
        U256::from(block_number),
        "invalid commitment"
    );

    let result = {
        let contract = Contract::new(address, &env);
        options.apply(contract.call_builder(&call)).call()
    };
    assert_eq!(
        result, preflight_result,
        "mismatch in preflight and execution"
    );

    result
}

/// Simple struct to operate over different [CallBuilder] types.
#[derive(Debug, Default)]
pub struct CallOptions {
    from: Option<Address>,
    gas: Option<u64>,
    gas_price: Option<U256>,
    access_list: Option<AccessList>,
}

#[allow(dead_code)]
impl CallOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_from(from: Address) -> Self {
        Self {
            from: Some(from),
            ..Default::default()
        }
    }
    pub fn with_gas(gas: u64) -> Self {
        Self {
            gas: Some(gas),
            ..Default::default()
        }
    }
    pub fn with_gas_price(gas_price: U256) -> Self {
        Self {
            gas_price: Some(gas_price),
            ..Default::default()
        }
    }
    pub fn with_access_list(access_list: AccessList) -> Self {
        Self {
            access_list: Some(access_list),
            ..Default::default()
        }
    }

    fn apply<E, C>(&self, mut builder: CallBuilder<E, C>) -> CallBuilder<E, C> {
        if let Some(from) = self.from {
            builder = builder.from(from);
        }
        if let Some(gas) = self.gas {
            builder = builder.gas(gas);
        }
        if let Some(gas_price) = self.gas_price {
            builder = builder.gas_price(gas_price);
        }
        builder
    }
}
