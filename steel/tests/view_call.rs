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

use alloy_primitives::{address, b256, uint, Address, U256};
use alloy_sol_types::{sol, SolCall};
use risc0_steel::{
    config::ETH_SEPOLIA_CHAIN_SPEC,
    ethereum::EthViewCallEnv,
    host::{
        provider::{CachedProvider, EthFileProvider, EthersProvider},
        EthersClient,
    },
    ViewCall,
};
use std::fmt::Debug;
use test_log::test;

const RPC_CACHE_FILE: &str = "testdata/rpc_cache.json";

const ERC20_TEST_CONTRACT: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7"); // USDT
const ERC20_TEST_BLOCK: u64 = 19493153;
sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

#[test]
fn erc20_balance_of() {
    let call = IERC20::balanceOfCall {
        account: address!("F977814e90dA44bFA03b6295A0616a897441aceC"), // Binance 8
    };

    let result = eth_call(ViewCall::new(call, ERC20_TEST_CONTRACT), ERC20_TEST_BLOCK);
    assert_eq!(result._0, uint!(3000000000000000_U256));
}

#[test]
fn erc20_multi_balance_of() {
    let view_call1 = ViewCall::new(
        IERC20::balanceOfCall {
            account: address!("F977814e90dA44bFA03b6295A0616a897441aceC"),
        },
        ERC20_TEST_CONTRACT,
    );
    let view_call2 = ViewCall::new(
        IERC20::balanceOfCall {
            account: address!("5a52E96BAcdaBb82fd05763E25335261B270Efcb"),
        },
        ERC20_TEST_CONTRACT,
    );

    // run the preflight
    let provider = EthFileProvider::from_file(&RPC_CACHE_FILE.into()).unwrap();
    let mut env = EthViewCallEnv::from_provider(provider, ERC20_TEST_BLOCK).unwrap();
    env.preflight(view_call1.clone()).unwrap();
    env.preflight(view_call2.clone()).unwrap();
    let input = env.into_zkvm_input().unwrap();

    // execute the call
    let env = input.into_env();
    let result = env.execute(view_call1);
    let result2 = env.execute(view_call2);
    assert_eq!(result._0, uint!(3000000000000000_U256));
    assert_eq!(result2._0, uint!(0x38d7ea4c68000_U256));
}

#[test]
fn uniswap_exact_output_single() {
    // mimic tx 0x241c81c3aa4c68cd07ae03a756050fc47fd91918a710250453d34c6db9d11997
    let block = 19493153;
    let caller = address!("f5213a6a2f0890321712520b8048D9886c1A9900");
    let contract = address!("E592427A0AEce92De3Edee1F18E0157C05861564"); // Uniswap V3
    sol! {
        #[derive(Debug, PartialEq, Eq)]
        interface ISwapRouter {
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
    }

    // swap USDT for 34.1973 WETH
    let call = ISwapRouter::exactOutputSingleCall {
        params: ISwapRouter::ExactOutputSingleParams {
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

    let view_call = ViewCall::new(call, contract).with_caller(caller);
    let result = eth_call(view_call, block);
    assert_eq!(result.amountIn, uint!(112537714517_U256));
}

const VIEW_CALL_TEST_CONTRACT: Address = address!("C5096d96dbC7594B3d0Ba50e708ba654A7ae1F3E");
const VIEW_CALL_TEST_BLOCK: u64 = 5702743;
sol!(
    #[derive(Debug, PartialEq, Eq)]
    contract ViewCallTest {
        /// Tests the SHA256 precompile.
        function testPrecompile() external view returns (bytes32) {
            (bool ok, bytes memory out) = address(0x02).staticcall("");
            require(ok);
            return abi.decode(out, (bytes32));
        }

        /// Tests accessing the code of a nonexistent account.
        function testNonexistentAccount() external view returns (uint256 size) {
            address a = address(uint160(block.prevrandao));
            assembly { size := extcodesize(a) }
        }

        /// Tests accessing the code of the EOA account 0x0000000000000000000000000000000000000000.
        function testEoaAccount() external view returns (uint256 size) {
            assembly { size := extcodesize(0) }
        }

        /// Tests the blockhash opcode.
        function testBlockhash() external view returns (bytes32) {
            return blockhash(block.number - 2);
        }

        /// Tests retrieving the chain ID.
        function testChainid() external view returns (uint256) {
            return block.chainid;
        }

        /// Tests retrieving the gas price.
        function testGasprice() external view returns (uint256) {
            return tx.gasprice;
        }

        /// Tests calling multiple contracts with the same and different storage.
        function testMuliContractCalls() external view returns (uint256) {
            return VALUE0.value() + VALUE42_a.value() + VALUE42_b.value();
        }
    }
);

#[test]
fn precompile() {
    let result = eth_call(
        ViewCall::new(ViewCallTest::testPrecompileCall {}, VIEW_CALL_TEST_CONTRACT),
        VIEW_CALL_TEST_BLOCK,
    );
    assert_eq!(
        result._0,
        b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

#[test]
fn nonexistent_account() {
    let result = eth_call(
        ViewCall::new(
            ViewCallTest::testNonexistentAccountCall {},
            VIEW_CALL_TEST_CONTRACT,
        ),
        VIEW_CALL_TEST_BLOCK,
    );
    assert_eq!(result.size, uint!(0_U256));
}

#[test]
fn eoa_account() {
    let result = eth_call(
        ViewCall::new(ViewCallTest::testEoaAccountCall {}, VIEW_CALL_TEST_CONTRACT),
        VIEW_CALL_TEST_BLOCK,
    );
    assert_eq!(result.size, uint!(0_U256));
}

#[test]
fn blockhash() {
    let result = eth_call(
        ViewCall::new(ViewCallTest::testBlockhashCall {}, VIEW_CALL_TEST_CONTRACT),
        VIEW_CALL_TEST_BLOCK,
    );
    assert_eq!(
        result._0,
        b256!("7703fe4a3d6031a579d52ce9e493e7907d376cfc3b41f9bc7710b0dae8c67f68")
    );
}

#[test]
fn chainid() {
    let result = eth_call(
        ViewCall::new(ViewCallTest::testChainidCall {}, VIEW_CALL_TEST_CONTRACT),
        VIEW_CALL_TEST_BLOCK,
    );
    assert_eq!(result._0, uint!(11155111_U256),);
}

#[test]
fn multi_contract_calls() {
    let result = eth_call(
        ViewCall::new(
            ViewCallTest::testMuliContractCallsCall {},
            VIEW_CALL_TEST_CONTRACT,
        ),
        VIEW_CALL_TEST_BLOCK,
    );
    assert_eq!(result._0, uint!(84_U256),);
}

#[test]
fn call_eoa() {
    let provider = EthFileProvider::from_file(&RPC_CACHE_FILE.into()).unwrap();
    let mut env = EthViewCallEnv::from_provider(provider, VIEW_CALL_TEST_BLOCK)
        .unwrap()
        .with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
    env.preflight(ViewCall::new(
        ViewCallTest::testBlockhashCall {},
        Address::ZERO,
    ))
    .expect_err("calling an EOA should fail");
}

fn eth_call<C>(view_call: ViewCall<C>, block: u64) -> C::Return
where
    C: SolCall + Clone,
    <C as SolCall>::Return: PartialEq + Debug,
{
    let provider = EthFileProvider::from_file(&RPC_CACHE_FILE.into()).unwrap();
    let mut env = EthViewCallEnv::from_provider(provider, block)
        .unwrap()
        .with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

    let preflight_result = env.preflight(view_call.clone()).unwrap();
    let input = env.into_zkvm_input().unwrap();

    let env = input.into_env().with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
    let result = env.execute(view_call);
    assert_eq!(
        result, preflight_result,
        "mismatch in preflight and execution"
    );

    result
}

/// Adds the required RPC data to the cache file.
#[allow(dead_code)]
fn golden<C: SolCall>(calls: impl IntoIterator<Item = ViewCall<C>>, block: u64) {
    let client = EthersClient::new_client("<RPC-URL>", 3, 500).unwrap();
    let provider = CachedProvider::new(RPC_CACHE_FILE.into(), EthersProvider::new(client)).unwrap();
    let mut env = EthViewCallEnv::from_provider(provider, block).unwrap();

    for call in calls {
        env.preflight(call).unwrap();
    }
    env.into_zkvm_input().unwrap();
}
