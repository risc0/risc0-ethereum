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

//! Tests that corrupting the input in various ways always leads to an error.
#![cfg(feature = "host")]

use std::{fs::File, io::BufReader, path::Path};

use crate::common::ANVIL_CHAIN_SPEC;
use alloy::{
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    transports::{
        http::{Client, Http},
        BoxFuture,
    },
};
use alloy_primitives::{address, Address, Bytes, B256, U256};
use anyhow::Context;
use risc0_steel::{
    ethereum::{EthBlockHeader, EthEvmEnv, EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC},
    host::BlockNumberOrTag,
    Commitment, Contract, StateAccount,
};
use serde_json::{from_value, to_value, Value};
use test_log::test;

#[allow(dead_code)]
mod common;

const RPC_URL: &str = "https://ethereum-sepolia-rpc.publicnode.com";
const BEACON_API_URL: &str = "https://ethereum-sepolia-beacon-api.publicnode.com";

const USDT_ADDRESS: Address = address!("aA8E23Fb1079EA71e0a56F48a2aA51851D8433D0");
const USDT_CALL: sol::IERC20::balanceOfCall = sol::IERC20::balanceOfCall {
    account: Address::ZERO,
};

const ANVIL_CONTRACT_ADDRESS: Address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
mod sol {
    alloy::sol! {
        // docker run -i ethereum/solc:0.8.26 - --optimize --bin
        #[sol(rpc, bytecode="6080604052348015600e575f80fd5b5060405160ec38038060ec8339810160408190526029916035565b5f919091556001556056565b5f80604083850312156045575f80fd5b505080516020909101519092909150565b608b8060615f395ff3fe6080604052348015600e575f80fd5b50600436106030575f3560e01c80630dbe671f1460345780634df7e3d014604d575b5f80fd5b603b5f5481565b60405190815260200160405180910390f35b603b6001548156fea2646970667358221220e02cbbf511cfb7f944c3eeed1371864dafc8020121b8c70a79d6f6d1543ee1d664736f6c634300081a0033")]
        contract Pair {
            uint256 public a;
            uint256 public b;

            constructor(uint256 _a, uint256 _b) {
                a = _a;
                b = _b;
            }
        }
    }
    alloy::sol! {
        // docker run -i ethereum/solc:0.8.26 - --optimize --bin
        #[sol(rpc, bytecode="6080604052348015600e575f80fd5b50607880601a5f395ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c8063502ec9a914602a575b5f80fd5b4360ff19014060405190815260200160405180910390f3fea2646970667358221220a1068fdd89e119c368442304fee89c4ab8d836ccdf929fa69a54db90fe9ab46464736f6c634300081a0033")]
        contract BlockHash {
            function get256() external view returns (bytes32 h) {
                assembly { h := blockhash(sub(number(), 256)) }
            }
        }
    }
    alloy::sol! {
        interface IERC20 {
            function balanceOf(address account) external view returns (uint);
        }
    }
}

/// Returns an Anvil provider with the deployed `Pair` contract.
async fn anvil_provider() -> impl Provider<Http<Client>> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_anvil_with_wallet_and_config(|anvil| anvil.args(["--hardfork", "cancun"]));
    let node_info = provider.anvil_node_info().await.unwrap();
    log::info!("Anvil started: {:?}", node_info);
    sol::Pair::deploy(&provider, U256::from(123456789), U256::from(987654321))
        .await
        .unwrap();

    provider
}

/// Creates an `EthEvmInput` using [anvil_provider] and preflighting `Pair.a()` and `Pair.b()`.
async fn anvil_input() -> anyhow::Result<EthEvmInput> {
    let mut env = EthEvmEnv::builder()
        .provider(anvil_provider().await)
        .build()
        .await?
        .with_chain_spec(&ANVIL_CHAIN_SPEC);
    Contract::preflight(ANVIL_CONTRACT_ADDRESS, &mut env)
        .call_builder(&sol::Pair::aCall {})
        .call()
        .await?;
    Contract::preflight(ANVIL_CONTRACT_ADDRESS, &mut env)
        .call_builder(&sol::Pair::bCall {})
        .call()
        .await?;

    env.into_input().await
}

/// Executes `Pair.a()` and `Pair.b()` on the input just as the guest would.
fn mock_anvil_guest(input: EthEvmInput) -> Commitment {
    let env = input.into_env().with_chain_spec(&ANVIL_CHAIN_SPEC);
    Contract::new(ANVIL_CONTRACT_ADDRESS, &env)
        .call_builder(&sol::Pair::aCall {})
        .call();
    Contract::new(ANVIL_CONTRACT_ADDRESS, &env)
        .call_builder(&sol::Pair::bCall {})
        .call();

    env.into_commitment()
}

/// Creates `EthEvmInput::Beacon` using live RPC nodes preflighting `IERC20(USDT).balanceOf(0x0)`.
async fn rpc_usdt_beacon_input() -> anyhow::Result<EthEvmInput> {
    let mut env = EthEvmEnv::builder()
        .rpc(RPC_URL.parse()?)
        .beacon_api(BEACON_API_URL.parse()?)
        .block_number_or_tag(BlockNumberOrTag::Parent)
        .build()
        .await?;
    env = env.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
    Contract::preflight(USDT_ADDRESS, &mut env)
        .call_builder(&USDT_CALL)
        .call()
        .await?;

    env.into_input().await
}

/// Loads the data from an existing JSON file, or creates it.
async fn load_or_create<'a, T: serde::ser::Serialize + serde::de::DeserializeOwned>(
    path: impl AsRef<Path>,
    f: impl Fn() -> BoxFuture<'a, anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let path = path.as_ref();
    if path.exists() {
        let f = File::open(path)?;
        Ok(serde_json::from_reader(BufReader::new(f))?)
    } else {
        log::warn!("Creating '{}' from scratch...", path.display());
        let input = f().await.context("failed to create data")?;
        serde_json::to_writer(File::create(path)?, &input)?;

        Ok(input)
    }
}

/// Returns the JSON representation of the inner `BlockInput`.
fn get_block_input_mut(input: &mut Value) -> &mut Value {
    let (key, value) = input.as_object_mut().unwrap().into_iter().next().unwrap();
    match key.as_str() {
        "Block" => value,
        "Beacon" => &mut value["input"],
        _ => unreachable!(),
    }
}

/// Returns the JSON representation of the value of any leaf-node in the trie.
fn get_leaf_val_mut(trie: &mut Value) -> Option<&mut Value> {
    match trie {
        Value::Null => None,
        Value::Object(node) => {
            let (key, value) = node.into_iter().next().unwrap();
            match key.as_str() {
                "Leaf" => Some(&mut value[1]),
                "Extension" => get_leaf_val_mut(&mut value[1]),
                "Branch" => {
                    let children = value.as_array_mut().unwrap();
                    children.iter_mut().find_map(|c| get_leaf_val_mut(c))
                }
                "Digest" => None,
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}

#[test(tokio::test)]
#[should_panic(expected = "No storage trie with root")]
async fn corrupt_storage_slot() {
    let input = anvil_input().await.unwrap();

    // get the JSON representation of the first storage trie
    let mut input_value = to_value(input).unwrap();
    let storage_trie_value = &mut get_block_input_mut(&mut input_value)["storage_tries"][0];

    // corrupt the storage slot value of the first leaf in the storage trie
    let slot_val = 0xdeadbeaf_u64;
    *get_leaf_val_mut(storage_trie_value).unwrap() = to_value(alloy_rlp::encode(slot_val)).unwrap();

    // executing this on the guest should panic
    mock_anvil_guest(from_value(input_value).unwrap());
}

#[test(tokio::test)]
#[should_panic(expected = "No storage trie with root")]
async fn corrupt_storage_trie() {
    let input = anvil_input().await.unwrap();

    // get the JSON representation of the first storage trie
    let mut input_value = to_value(input).unwrap();
    let storage_trie_value = &mut get_block_input_mut(&mut input_value)["storage_tries"][0];

    // corrupt the trie by getting the first child node and deleting it
    let child_array = storage_trie_value["Branch"].as_array_mut().unwrap();
    let child_value = child_array.iter_mut().find(|c| !c.is_null()).unwrap();
    *child_value = Value::Null;

    // executing this on the guest should panic
    mock_anvil_guest(from_value(input_value).unwrap());
}

#[test(tokio::test)]
#[should_panic(expected = "State root mismatch")]
async fn corrupt_state_account() {
    let input = anvil_input().await.unwrap();

    // get the JSON representation of the state trie
    let mut input_value = to_value(&input).unwrap();
    let state_trie = &mut get_block_input_mut(&mut input_value)["state_trie"];

    // get the account corresponding to the first leaf in the state trie
    let account_value = get_leaf_val_mut(state_trie).unwrap();
    let account_rlp = from_value::<Bytes>(account_value.clone()).unwrap();
    let mut account: StateAccount = alloy_rlp::decode_exact(account_rlp).unwrap();

    // corrupt the balance of that account
    account.balance = U256::from(0xdeadbeaf_u64);
    *account_value = to_value(alloy_rlp::encode(account)).unwrap();

    // executing this on the guest should panic
    mock_anvil_guest(from_value(input_value).unwrap());
}

#[test(tokio::test)]
#[should_panic(expected = "State root mismatch")]
async fn corrupt_state_trie() {
    let input = anvil_input().await.unwrap();

    // get the JSON representation of the state trie
    let mut input_value = to_value(&input).unwrap();
    let state_trie_value = &mut get_block_input_mut(&mut input_value)["state_trie"];

    // corrupt the trie by getting the first child node and deleting it
    let children = state_trie_value["Branch"].as_array_mut().unwrap();
    let child_value = children.iter_mut().find(|c| !c.is_null()).unwrap();
    *child_value = Value::Null;

    // executing this on the guest should panic
    mock_anvil_guest(from_value(input_value).unwrap());
}

#[test(tokio::test)]
#[should_panic(expected = "No code with hash")]
async fn corrupt_contract_code() {
    let input = anvil_input().await.unwrap();

    // get the JSON representation of byte code of the first contract
    let mut input_value = to_value(&input).unwrap();
    let contract_value = &mut get_block_input_mut(&mut input_value)["contracts"][0];

    // corrupt that contract by changing its bytecode
    *contract_value = to_value(&sol::BlockHash::BYTECODE).unwrap();

    // executing this on the guest should panic
    mock_anvil_guest(from_value(input_value).unwrap());
}

#[test(tokio::test)]
#[should_panic(expected = "Invalid ancestor chain")]
async fn corrupt_ancestor() {
    let provider = anvil_provider().await;
    // deploy the contract and mine more blocks to assure that the chain is long enough
    let address = {
        let instance = sol::BlockHash::deploy(&provider).await.unwrap();
        *instance.address()
    };
    provider
        .anvil_mine(Some(U256::from(256)), None)
        .await
        .unwrap();

    // create the corresponding input
    let mut env = EthEvmEnv::builder()
        .provider(provider)
        .build()
        .await
        .unwrap()
        .with_chain_spec(&ANVIL_CHAIN_SPEC);
    Contract::preflight(address, &mut env)
        .call_builder(&sol::BlockHash::get256Call {})
        .call()
        .await
        .unwrap();
    let input = env.into_input().await.unwrap();

    // get the JSON representation of the first (latest) ancestor block header
    let mut input_value = to_value(&input).unwrap();
    let ancestor_value = &mut get_block_input_mut(&mut input_value)["ancestors"][0];

    // corrupt the header by modifying its timestamp
    let mut header: EthBlockHeader = from_value(ancestor_value.clone()).unwrap();
    header.inner_mut().timestamp = 0xdeadbeaf;
    *ancestor_value = to_value(header).unwrap();

    // executing this on the guest should panic
    mock_anvil_guest(from_value(input_value).unwrap());
}

#[test(tokio::test)]
#[should_panic(expected = "Invalid commitment")]
async fn corrupt_header_block_commitment() {
    let input = anvil_input().await.unwrap();
    let exp_commit = input.clone().into_env().into_commitment();

    // get the JSON representation of the block header for the state
    let mut input_value = to_value(&input).unwrap();
    let header_value = &mut get_block_input_mut(&mut input_value)["header"];

    // corrupt the header by modifying its timestamp
    let mut header: EthBlockHeader = from_value(header_value.clone()).unwrap();
    header.inner_mut().timestamp = 0xdeadbeaf;
    *header_value = to_value(header).unwrap();

    // executing this should lead to an Invalid commitment
    let commit = mock_anvil_guest(from_value(input_value).unwrap());
    assert_eq!(commit.id, exp_commit.id, "Commitment changed");
    assert_eq!(commit.digest, exp_commit.digest, "Invalid commitment");
}

fn mock_usdt_guest(input: EthEvmInput) -> Commitment {
    let env = input.into_env().with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
    Contract::new(USDT_ADDRESS, &env)
        .call_builder(&USDT_CALL)
        .call();
    env.into_commitment()
}

#[test(tokio::test)]
#[should_panic(expected = "Invalid commitment")]
async fn corrupt_header_beacon_commitment() {
    let input = load_or_create("testdata/beacon_input.json", || {
        Box::pin(rpc_usdt_beacon_input())
    })
    .await
    .unwrap();
    let exp_commit = input.clone().into_env().into_commitment();

    // get the JSON representation of the block header for the state
    let mut input_value = to_value(&input).unwrap();
    let header_value = &mut get_block_input_mut(&mut input_value)["header"];

    // corrupt the header by modifying its number
    let mut header: EthBlockHeader = from_value(header_value.clone()).unwrap();
    header.inner_mut().number = 0xdeadbeaf;
    *header_value = to_value(header).unwrap();

    // executing this should lead to an Invalid commitment
    let commit = mock_usdt_guest(from_value(input_value).unwrap());
    assert_eq!(commit.id, exp_commit.id, "Changed commitment");
    assert_eq!(commit.digest, exp_commit.digest, "Invalid commitment");
}

#[test(tokio::test)]
#[should_panic(expected = "Invalid commitment")]
async fn corrupt_beacon_proof() {
    let input = load_or_create("testdata/beacon_input.json", || {
        Box::pin(rpc_usdt_beacon_input())
    })
    .await
    .unwrap();
    let exp_commit = input.clone().into_env().into_commitment();

    // get the JSON representation of the block header for the state
    let mut input_value = to_value(&input).unwrap();
    let proof_value = &mut input_value["Beacon"]["commit"]["proof"];

    // corrupt the first element in the Merkle path to something non-zero
    proof_value[0] = to_value(B256::with_last_byte(0x01)).unwrap();

    // executing this should lead to an Invalid commitment
    let commit = mock_usdt_guest(from_value(input_value).unwrap());
    assert_eq!(commit.id, exp_commit.id, "Changed commitment");
    assert_eq!(commit.digest, exp_commit.digest, "Invalid commitment");
}

#[test(tokio::test)]
#[should_panic(expected = "Invalid beacon inclusion proof")]
async fn corrupt_beacon_proof_length() {
    let input = load_or_create("testdata/beacon_input.json", || {
        Box::pin(rpc_usdt_beacon_input())
    })
    .await
    .unwrap();

    // get the JSON representation of the block header for the state
    let mut input_value = to_value(&input).unwrap();
    let proof_value = &mut input_value["Beacon"]["commit"]["proof"];

    // corrupt the proof by appending a new value
    let proof = proof_value.as_array_mut().unwrap();
    proof.push(to_value(B256::ZERO).unwrap());

    // converting this into an environment should panic
    mock_usdt_guest(from_value(input_value).unwrap());
}

#[cfg(feature = "unstable-history")]
mod history {
    use super::*;
    use test_log::test;

    /// Creates `EthEvmInput::History` using live RPC nodes preflighting `IERC20(USDT).balanceOf(0x0)`.
    async fn rpc_usdt_history_input() -> anyhow::Result<EthEvmInput> {
        let mut env = EthEvmEnv::builder()
            .rpc(RPC_URL.parse()?)
            .beacon_api(BEACON_API_URL.parse()?)
            .block_number_or_tag(BlockNumberOrTag::Safe)
            .commitment_block(BlockNumberOrTag::Parent)
            .build()
            .await?;
        env = env.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);
        Contract::preflight(USDT_ADDRESS, &mut env)
            .call_builder(&USDT_CALL)
            .call()
            .await?;

        env.into_input().await
    }

    #[test(tokio::test)]
    #[should_panic(expected = "Invalid commitment")]
    async fn corrupt_history_proof() {
        let input = load_or_create("testdata/history_input.json", || {
            Box::pin(rpc_usdt_history_input())
        })
        .await
        .unwrap();
        let exp_commit = input.clone().into_env().into_commitment();

        // get the JSON representation of the block header for the state
        let mut input_value = to_value(&input).unwrap();
        let state_commit = &mut input_value["History"]["commit"]["state_commits"][0];
        let proof_value = &mut state_commit["state_commit"]["proof"];

        // corrupt the first element in the Merkle path to something non-zero
        proof_value[0] = to_value(B256::with_last_byte(0x01)).unwrap();

        // executing this should lead to an Invalid commitment
        let commit = mock_usdt_guest(from_value(input_value).unwrap());
        assert_eq!(commit.id, exp_commit.id, "Changed commitment");
        assert_eq!(commit.digest, exp_commit.digest, "Invalid commitment");
    }

    #[test(tokio::test)]
    #[should_panic(expected = "Invalid commitment")]
    async fn corrupt_history_state_trie() {
        let input = load_or_create("testdata/history_input.json", || {
            Box::pin(rpc_usdt_history_input())
        })
        .await
        .unwrap();
        let exp_commit = input.clone().into_env().into_commitment();

        // get the JSON representation of the block header for the state
        let mut input_value = to_value(&input).unwrap();
        let state_commit = &mut input_value["History"]["commit"]["state_commits"][0];
        let state_trie_value = &mut state_commit["state"]["state_trie"];

        // corrupt the trie by getting the first child node and deleting it
        let children = state_trie_value["Branch"].as_array_mut().unwrap();
        let child_value = children.iter_mut().find(|c| !c.is_null()).unwrap();
        *child_value = Value::Null;

        // executing this should lead to an Invalid commitment
        let commit = mock_usdt_guest(from_value(input_value).unwrap());
        assert_eq!(commit.id, exp_commit.id, "Changed commitment");
        assert_eq!(commit.digest, exp_commit.digest, "Invalid commitment");
    }

    #[test(tokio::test)]
    #[should_panic(expected = "Beacon roots contract failed: InvalidState")]
    async fn corrupt_history_storage_trie() {
        let input = load_or_create("testdata/history_input.json", || {
            Box::pin(rpc_usdt_history_input())
        })
        .await
        .unwrap();

        // get the JSON representation of the block header for the state
        let mut input_value = to_value(&input).unwrap();
        let state_commit = &mut input_value["History"]["commit"]["state_commits"][0];
        let storage_trie_value = &mut state_commit["state"]["storage_trie"];

        // corrupt the trie by getting the first child node and deleting it
        let children = storage_trie_value["Branch"].as_array_mut().unwrap();
        let child_value = children.iter_mut().find(|c| !c.is_null()).unwrap();
        *child_value = Value::Null;

        // executing this on the guest should panic
        mock_usdt_guest(from_value(input_value).unwrap());
    }

    #[test(tokio::test)]
    #[should_panic(expected = "Beacon root does not match")]
    async fn corrupt_history_evm_commit_proof() {
        let input = load_or_create("testdata/history_input.json", || {
            Box::pin(rpc_usdt_history_input())
        })
        .await
        .unwrap();

        // get the JSON representation of the block header for the state
        let mut input_value = to_value(&input).unwrap();
        let evm_commit = &mut input_value["History"]["commit"]["evm_commit"];

        // corrupt the EVM commit by changing the first element in the proof to something non-zero
        let proof_value = &mut evm_commit["proof"];
        proof_value[0] = to_value(B256::with_last_byte(0x01)).unwrap();

        // executing this on the guest should panic
        mock_usdt_guest(from_value(input_value).unwrap());
    }

    #[test(tokio::test)]
    #[should_panic(expected = "Unresolved node access")]
    async fn corrupt_history_evm_commit_timestamp() {
        let input = load_or_create("testdata/history_input.json", || {
            Box::pin(rpc_usdt_history_input())
        })
        .await
        .unwrap();

        // get the JSON representation of the block header for the state
        let mut input_value = to_value(&input).unwrap();
        let evm_commit = &mut input_value["History"]["commit"]["evm_commit"];

        // corrupt the EVM commit by changing its timestamp
        let timestamp_value = &mut evm_commit["timestamp"];
        *timestamp_value = to_value(u64::MAX).unwrap();

        // converting this into an environment should panic
        mock_usdt_guest(from_value(input_value).unwrap());
    }
}
