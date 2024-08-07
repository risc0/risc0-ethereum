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
    network::{Ethereum, EthereumWallet},
    providers::{
        ext::AnvilApi,
        fillers::{FillProvider, JoinFill, RecommendedFiller, WalletFiller},
        layers::AnvilProvider,
        ProviderBuilder, RootProvider,
    },
    transports::http::{Client, Http},
    uint,
};
use alloy_primitives::{address, b256, Address, U256};
use common::{CallOptions, ANVIL_CHAIN_SPEC};
use risc0_steel::{ethereum::EthEvmEnv, host::BlockNumberOrTag, Contract};
use test_log::test;

mod common;

const STEEL_TEST_CONTRACT: Address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
alloy::sol!(
    // docker run -i ethereum/solc:0.8.26 - --optimize --bin
    #[sol(rpc, bytecode="60e060405234801561000f575f80fd5b505f60405161001d906100c4565b908152602001604051809103905ff08015801561003c573d5f803e3d5ffd5b506001600160a01b0316608052604051602a90610058906100c4565b908152602001604051809103905ff080158015610077573d5f803e3d5ffd5b506001600160a01b031660a052604051602a90610093906100c4565b908152602001604051809103905ff0801580156100b2573d5f803e3d5ffd5b506001600160a01b031660c0526100d0565b60c98061041e83390190565b60805160a05160c0516103256100f95f395f60de01525f61015e01525f6101de01526103255ff3fe608060405234801561000f575f80fd5b5060043610610085575f3560e01c8063445bda4311610058578063445bda43146100ba5780637d732b5f146100c25780639f6f32aa146100c8578063ab8fd80c146100d0575f80fd5b80630692d13c146100895780632e8bde391461009f57806330e49663146100ad57806341317185146100b3575b5f80fd5b5f3b5b6040519081526020015b60405180910390f35b604051328152602001610096565b3a61008c565b443b61008c565b61008c6100db565b4661008c565b61008c610275565b4360ff19014061008c565b5f7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610138573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061015c91906102b3565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101b8573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101dc91906102b3565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610238573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061025c91906102b3565b61026691906102ca565b61027091906102ca565b905090565b6040515f906002906020818481855afa158015610294573d5f803e3d5ffd5b5050506040513d601f19601f8201168201806040525081019061027091905b5f602082840312156102c3575f80fd5b5051919050565b808201808211156102e957634e487b7160e01b5f52601160045260245ffd5b9291505056fea2646970667358221220da3a26098dd43c05acc2240a43d0fc9fcbddfefe20da8b1b7b298a9deb28c08f64736f6c634300081a00336080604052348015600e575f80fd5b5060405160c938038060c9833981016040819052602991602f565b5f556045565b5f60208284031215603e575f80fd5b5051919050565b60798060505f395ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c80633fa4f24514602a575b5f80fd5b60315f5481565b60405190815260200160405180910390f3fea2646970667358221220ae38f162affb03bb6f61ae063b82ed619bbef90cd2349cf62045b42e5366a10064736f6c634300081a0033")]
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

        /// Tests the SHA256 precompile.
        function testPrecompile() external pure returns (bytes32) {
            return sha256("");
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

type TestProvider = FillProvider<
    JoinFill<RecommendedFiller, WalletFiller<EthereumWallet>>,
    AnvilProvider<RootProvider<Http<Client>>, Http<Client>>,
    Http<Client>,
    Ethereum,
>;

/// Returns an Anvil provider with the deployed [SteelTest] contract.
async fn test_provider() -> TestProvider {
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
async fn precompile() {
    let result = common::eth_call(
        test_provider().await,
        STEEL_TEST_CONTRACT,
        SteelTest::testPrecompileCall {},
        CallOptions::new(),
    )
    .await;
    assert_eq!(
        result._0,
        b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
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
    let mut env = EthEvmEnv::from_provider(test_provider().await, BlockNumberOrTag::Latest)
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
