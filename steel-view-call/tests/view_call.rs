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

#![cfg(feature = "host")]

use alloy_primitives::{address, uint, Address, BlockNumber, U256};
use alloy_sol_types::{sol, SolCall};
use risc0_ethereum_view_call::{
    ethereum::EthViewCallEnv,
    host::{
        provider::{CachedProvider, EthFileProvider, EthersProvider},
        EthersClient,
    },
    ViewCall,
};
use test_log::test;

const BLOCK: BlockNumber = 19493153;
const RPC_CACHE_FILE: &str = "testdata/rpc_cache.json";

#[test]
fn erc20_balance_of() {
    let contract = address!("dAC17F958D2ee523a2206206994597C13D831ec7"); // USDT
    sol! {
        function balanceOf(address account) external view returns (uint);
    }
    let call = balanceOfCall {
        account: address!("F977814e90dA44bFA03b6295A0616a897441aceC"), // Binance 8
    };

    // run the preflight
    let provider = EthFileProvider::from_file(&RPC_CACHE_FILE.into()).unwrap();
    let env = EthViewCallEnv::from_provider(provider, BLOCK).unwrap();
    let (input, _) = ViewCall::new(call.clone(), contract)
        .preflight(env)
        .unwrap();

    // execute the call
    let env = input.into_env();
    let result = ViewCall::new(call, contract).execute(env);
    assert_eq!(result._0, uint!(3000000000000000_U256));
}

#[test]
fn uniswap_exact_output_single() {
    // mimic tx 0x241c81c3aa4c68cd07ae03a756050fc47fd91918a710250453d34c6db9d11997
    let caller = address!("f5213a6a2f0890321712520b8048D9886c1A9900");
    let contract = address!("E592427A0AEce92De3Edee1F18E0157C05861564"); // Uniswap V3
    sol! {
       struct ExactOutputSingleParams {
           address tokenIn;
           address tokenOut;
           uint24 fee;
           address recipient;
           uint256 deadline;
           uint256 amountOut;
           uint256 amountInMaximum;
           uint160 sqrtPriceLimitX96;
       }

       function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn);
    }

    // swap USDT for 34.1973 WETH
    let call = exactOutputSingleCall {
        params: ExactOutputSingleParams {
            tokenIn: address!("dAC17F958D2ee523a2206206994597C13D831ec7"), // USDT
            tokenOut: address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), // WETH
            fee: 500,
            recipient: caller,
            deadline: uint!(1711146836_U256),
            amountOut: uint!(34197300000000000000_U256),
            amountInMaximum: U256::MAX,
            sqrtPriceLimitX96: U256::ZERO,
        },
    };

    // run the preflight
    let provider = EthFileProvider::from_file(&RPC_CACHE_FILE.into()).unwrap();
    let env = EthViewCallEnv::from_provider(provider, BLOCK).unwrap();
    let (input, _) = ViewCall::new(call.clone(), contract)
        .with_caller(caller)
        .preflight(env)
        .unwrap();

    // execute the call
    let env = input.into_env();
    let result = ViewCall::new(call, contract)
        .with_caller(caller)
        .execute(env);
    assert_eq!(result.amountIn, uint!(112537714517_U256));
}

/// Adds the required RPC data to the cache file.
#[allow(dead_code)]
fn golden(call: impl SolCall, contract: Address, caller: Address) {
    let client = EthersClient::new_client("<RPC-URL>", 3, 500).unwrap();
    let provider = CachedProvider::new(RPC_CACHE_FILE.into(), EthersProvider::new(client)).unwrap();
    let env = EthViewCallEnv::from_provider(provider, BLOCK).unwrap();

    ViewCall::new(call, contract)
        .with_caller(caller)
        .preflight(env)
        .unwrap();
}
