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

use std::fmt::Debug;

use alloy::{
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    transports::http::{Client, Http},
    uint,
};
use alloy_primitives::{address, b256, bytes, hex, Address, Bytes, U256};
use alloy_sol_types::SolCall;
use common::{CallOptions, ANVIL_CHAIN_SPEC};
use risc0_steel::{ethereum::EthEvmEnv, Contract};
use sha2::{Digest, Sha256};
use test_log::test;

mod common;

const STEEL_TEST_CONTRACT: Address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
alloy::sol!(
    // docker run -i ethereum/solc:0.8.26 - --optimize --bin
    #[sol(rpc, bytecode="60e060405234801561000f575f80fd5b505f60405161001d906100c4565b908152602001604051809103905ff08015801561003c573d5f803e3d5ffd5b506001600160a01b0316608052604051602a90610058906100c4565b908152602001604051809103905ff080158015610077573d5f803e3d5ffd5b506001600160a01b031660a052604051602a90610093906100c4565b908152602001604051809103905ff0801580156100b2573d5f803e3d5ffd5b506001600160a01b031660c0526100d0565b60c98061064e83390190565b60805160a05160c0516105546100fa5f395f6101b901525f61023901525f6102b901526105545ff3fe608060405234801561000f575f80fd5b50600436106100a6575f3560e01c8063413171851161006e5780634131718514610107578063445bda431461010e57806370239222146101165780637d732b5f1461011e578063ab8fd80c14610124578063d62f7a421461012f575f80fd5b80630692d13c146100aa578063163e004a146100c05780631e79fe8c146100c75780632e8bde39146100e757806330e4966314610101575b5f80fd5b5f3b5b6040519081526020015b60405180910390f35b5f546100ad565b6100da6100d53660046103f7565b610142565b6040516100b79190610465565b325b6040516001600160a01b0390911681526020016100b7565b3a6100ad565b443b6100ad565b6100ad6101b6565b6100ad610350565b466100ad565b4360ff1901406100ad565b6100e961013d36600461049a565b610392565b60605f80600a6001600160a01b031685856040516101619291906104d9565b5f60405180830381855afa9150503d805f8114610199576040519150601f19603f3d011682016040523d82523d5f602084013e61019e565b606091505b5091509150816101ac575f80fd5b9150505b92915050565b5f7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610213573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061023791906104e8565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610293573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906102b791906104e8565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610313573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061033791906104e8565b61034191906104ff565b61034b91906104ff565b905090565b6040515f906002906020818481855afa15801561036f573d5f803e3d5ffd5b5050506040513d601f19601f8201168201806040525081019061034b91906104e8565b604080515f8082526020820180845287905260ff861692820192909252606081018490526080810183905260019060a0016020604051602081039080840390855afa1580156103e3573d5f803e3d5ffd5b5050604051601f1901519695505050505050565b5f8060208385031215610408575f80fd5b823567ffffffffffffffff81111561041e575f80fd5b8301601f8101851361042e575f80fd5b803567ffffffffffffffff811115610444575f80fd5b856020828401011115610455575f80fd5b6020919091019590945092505050565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f83011684010191505092915050565b5f805f80608085870312156104ad575f80fd5b84359350602085013560ff811681146104c4575f80fd5b93969395505050506040820135916060013590565b818382375f9101908152919050565b5f602082840312156104f8575f80fd5b5051919050565b808201808211156101b057634e487b7160e01b5f52601160045260245ffdfea264697066735822122075dab15b6b833f12828453c07f6064f3d73d2b3056968cae053a337303dd249b64736f6c634300081a00336080604052348015600e575f80fd5b5060405160c938038060c9833981016040819052602991602f565b5f556045565b5f60208284031215603e575f80fd5b5051919050565b60798060505f395ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c80633fa4f24514602a575b5f80fd5b60315f5481565b60405190815260200160405180910390f3fea2646970667358221220120e1fe19e13f245d9779578380d3ba162142d3e5bf63f5e5f83dbe878cdb44464736f6c634300081a0033")]
    #[derive(Debug, PartialEq, Eq)]
    contract SteelTest {
        Value internal immutable VALUE0;
        Value internal immutable VALUE42A;
        Value internal immutable VALUE42B;

        constructor() {
            VALUE0 = new Value(0);
            VALUE42A = new Value(42);
            VALUE42B = new Value(42);
        }

        /// Tests the ecRecover precompile.
        function testECRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
            return ecrecover(hash, v, r, s);
        }

        /// Tests the SHA256 precompile.
        function testSHA256() external pure returns (bytes32) {
            return sha256("");
        }

        /// Tests the EIP-4844 point evaluation precompile.
        function testPointEvaluationPrecompile(bytes calldata input) external view returns (bytes memory) {
            (bool ok, bytes memory out) = address(0x0A).staticcall(input);
            require(ok);
            return out;
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
        function testBlockhash() external view returns (bytes32 h) {
            assembly { h := blockhash(sub(number(), 256)) }
        }

        /// Tests retrieving the chain ID.
        function testChainid() external view returns (uint256) {
            return block.chainid;
        }

        /// Tests retrieving the address of the sender of the transaction.
        function testOrigin() external view returns (address) {
            return tx.origin;
        }

        /// Tests retrieving the gas price.
        function testGasprice() external view returns (uint256) {
            return tx.gasprice;
        }

        /// Tests loading a word from storage of an account with empty storage.
        function testLoadEmptyStorage() external view returns (uint256 val) {
            assembly { val := sload(0) }
        }

        /// Tests calling multiple contracts with the same and different storage.
        function testMuliContractCalls() external view returns (uint256) {
            return VALUE0.value() + VALUE42A.value() + VALUE42B.value();
        }
    }

    contract Value {
        uint256 public value;

        constructor(uint256 _value) {
            value = _value;
        }
    }
);

/// Returns an Anvil provider with the deployed [SteelTest] contract.
async fn test_provider() -> impl Provider<Http<Client>> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_anvil_with_wallet_and_config(|anvil| anvil.args(["--hardfork", "cancun"]));
    let node_info = provider.anvil_node_info().await.unwrap();
    log::info!("Anvil started: {:?}", node_info);
    let instance = SteelTest::deploy(&provider).await.unwrap();
    assert_eq!(*instance.address(), STEEL_TEST_CONTRACT);

    provider
}

#[test(tokio::test)]
async fn ec_recover() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testECRecoverCall {
            hash: b256!("385967023fb9520b497ee37da9c1e3d5faac1385800ce4ed07ca32d7893c7bb5"),
            v: 27,
            r: b256!("905eadefa07b89ede807aee158ad7ef0414838a9c084e4192029e0383d000b84"),
            s: b256!("250f8aab57d60992fd1fa4fd681491575e74b1c5691ebc631ac2326beb23c5c7"),
        },
        CallOptions::new(),
    )
    .await;
    assert_eq!(
        result._0,
        address!("328809Bc894f92807417D2dAD6b7C998c1aFdac6")
    );
}

#[test(tokio::test)]
async fn sha256() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testSHA256Call {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(
        result._0,
        b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

// TODO(#237): EIP-4844 point evaluation precompile is not currently enabled.
#[test(tokio::test)]
#[should_panic(expected = "EVM error: c-kzg feature is not enabled")]
async fn point_evaluation_precompile() {
    // test data from: https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_31ebd010e6098750/data.yaml
    let commitment = hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7").to_vec();
    let mut versioned_hash = Sha256::digest(&commitment).to_vec();
    versioned_hash[0] = 0x01;
    let z = b256!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000").to_vec();
    let y = b256!("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9").to_vec();
    let proof = hex!("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c").to_vec();
    let input = Bytes::from([versioned_hash, z, y, commitment, proof].concat());

    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testPointEvaluationPrecompileCall { input },
        CallOptions::new(),
    )
    .await;
    assert_eq!(
        result._0,
        bytes!("000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
    );
}

#[test(tokio::test)]
async fn nonexistent_account() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testNonexistentAccountCall {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(result.size, uint!(0_U256));
}

#[test(tokio::test)]
async fn eoa_account() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testEoaAccountCall {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(result.size, uint!(0_U256));
}

#[test(tokio::test)]
async fn blockhash() {
    let provider = test_provider().await;
    let block_hash = provider.anvil_node_info().await.unwrap().current_block_hash;
    // mine more blocks to assure that the chain is long enough
    provider
        .anvil_mine(Some(U256::from(256)), None)
        .await
        .unwrap();

    let result = common::eth_call(
        provider,
        STEEL_TEST_CONTRACT,
        SteelTest::testBlockhashCall {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(result.h, block_hash);
}

#[test(tokio::test)]
async fn chainid() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testChainidCall {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(result._0, uint!(31337_U256));
}

#[test(tokio::test)]
async fn origin() {
    let from = address!("0000000000000000000000000000000000000042");
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testOriginCall {},
        CallOptions::with_from(from),
    )
    .await;
    assert_eq!(result._0, from);
}

#[test(tokio::test)]
async fn gasprice() {
    let gas_price = uint!(42_U256);
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testGaspriceCall {},
        CallOptions::with_gas_price(gas_price),
    )
    .await;
    assert_eq!(result._0, gas_price);
}

#[test(tokio::test)]
async fn load_empty_storage() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testLoadEmptyStorageCall {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(result.val, uint!(0_U256));
}

#[test(tokio::test)]
async fn multi_contract_calls() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testMuliContractCallsCall {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(result._0, uint!(84_U256));
}

#[test(tokio::test)]
async fn call_eoa() {
    let mut env = EthEvmEnv::builder()
        .provider(test_provider().await)
        .build()
        .await
        .unwrap()
        .with_chain_spec(&ANVIL_CHAIN_SPEC);
    let mut contract = Contract::preflight(Address::ZERO, &mut env);
    contract
        .call_builder(&SteelTest::testBlockhashCall {})
        .call()
        .await
        .expect_err("calling an EOA should fail");
}

#[test(tokio::test)]
async fn no_preflight() {
    let env = EthEvmEnv::builder()
        .provider(test_provider().await)
        .build()
        .await
        .unwrap()
        .with_chain_spec(&ANVIL_CHAIN_SPEC);
    match env.into_input().await {
        Ok(_) => panic!("calling into_input without a preflight should fail"),
        Err(err) => assert_eq!(
            err.to_string(),
            "no accounts accessed: use Contract::preflight"
        ),
    }
}

alloy::sol!(
    // docker run -i ethereum/solc:0.8.26 - --optimize --bin
    #[sol(rpc, bytecode="60a0604052348015600e575f80fd5b5060405161012a38038061012a833981016040819052602b91604b565b60808190525f5b6080518110156045576001808255016032565b50506061565b5f60208284031215605a575f80fd5b5051919050565b60805160b46100765f395f6047015260b45ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c8063380eb4e014602a575b5f80fd5b60306042565b60405190815260200160405180910390f35b5f805b7f0000000000000000000000000000000000000000000000000000000000000000811015607a57805491909101906001016045565b509056fea26469706673582212203687b75eefdd9cc7ceedb243aa360bd9e1b4cab1930149a371efef74ce18bdf164736f6c634300081a0033")]
    #[derive(Debug, PartialEq, Eq)]
    contract SlotsTest {
        uint256 internal immutable N;

        constructor(uint256 n) {
            N = n;
            for (uint256 i = 0; i < N; i++) {
                assembly { sstore(i, 1) }
            }
        }

        function sload() external view returns (uint256 sum) {
            for (uint256 i = 0; i < N; i++) {
                assembly { sum := add(sum, sload(i)) }
            }
        }
    }
);

#[test(tokio::test)]
async fn prefetch_access_list() {
    const NUM_SLOTS: U256 = uint!(1_250_U256);

    let provider = test_provider().await;
    let instance = SlotsTest::deploy(&provider, NUM_SLOTS).await.unwrap();
    let address = *instance.address();
    let call = SlotsTest::sloadCall {};

    let mut access_list = {
        let tx = TransactionRequest::default()
            .from(address)
            .to(address)
            .input(call.abi_encode().into());
        let access_list_with_gas_used = provider.create_access_list(&tx).await.unwrap();
        access_list_with_gas_used.access_list
    };
    // remove one storage proof from the access list
    access_list.0.first_mut().unwrap().storage_keys.pop();
    let options = CallOptions::with_access_list(access_list);

    common::eth_call(provider, address, call, options).await;
}
