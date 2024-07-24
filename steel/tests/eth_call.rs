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

use alloy::{
    network::{Ethereum, EthereumWallet},
    providers::{
        ext::AnvilApi,
        fillers::{FillProvider, JoinFill, RecommendedFiller, WalletFiller},
        layers::AnvilProvider,
        ProviderBuilder, RootProvider,
    },
    rpc::types::BlockNumberOrTag,
    transports::http::{Client, Http},
};
use alloy_primitives::{address, b256, uint, Address, U256};
use alloy_sol_types::SolCall;
use once_cell::sync::Lazy;
use revm::primitives::SpecId;
use risc0_steel::{
    config::{ChainSpec, EIP1559_CONSTANTS_DEFAULT},
    ethereum::EthEvmEnv,
    CallBuilder, Contract, EvmBlockHeader,
};
use std::fmt::Debug;
use test_log::test;

const STEEL_TEST_CONTRACT: Address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
alloy::sol!(
    #[sol(rpc, bytecode="60e060405234801561000f575f80fd5b505f60405161001d906100c4565b908152602001604051809103905ff08015801561003c573d5f803e3d5ffd5b506001600160a01b0316608052604051602a90610058906100c4565b908152602001604051809103905ff080158015610077573d5f803e3d5ffd5b506001600160a01b031660a052604051602a90610093906100c4565b908152602001604051809103905ff0801580156100b2573d5f803e3d5ffd5b506001600160a01b031660c0526100d0565b60c98061041e83390190565b60805160a05160c0516103256100f95f395f60de01525f61015e01525f6101de01526103255ff3fe608060405234801561000f575f80fd5b5060043610610085575f3560e01c8063445bda4311610058578063445bda43146100ba5780637d732b5f146100c25780639f6f32aa146100c8578063ab8fd80c146100d0575f80fd5b80630692d13c146100895780632e8bde391461009f57806330e49663146100ad57806341317185146100b3575b5f80fd5b5f3b5b6040519081526020015b60405180910390f35b604051328152602001610096565b3a61008c565b443b61008c565b61008c6100db565b4661008c565b61008c610275565b4360fe19014061008c565b5f7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610138573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061015c91906102b3565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101b8573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906101dc91906102b3565b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316633fa4f2456040518163ffffffff1660e01b8152600401602060405180830381865afa158015610238573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061025c91906102b3565b61026691906102ca565b61027091906102ca565b905090565b6040515f906002906020818481855afa158015610294573d5f803e3d5ffd5b5050506040513d601f19601f8201168201806040525081019061027091905b5f602082840312156102c3575f80fd5b5051919050565b808201808211156102e957634e487b7160e01b5f52601160045260245ffd5b9291505056fea264697066735822122017cd88097c7ec4827d02d5b993a5a0735d07aaa06059c5e6c23f0ee89f66264b64736f6c634300081900336080604052348015600e575f80fd5b5060405160c938038060c9833981016040819052602991602f565b5f556045565b5f60208284031215603e575f80fd5b5051919050565b60798060505f395ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c80633fa4f24514602a575b5f80fd5b60315f5481565b60405190815260200160405180910390f3fea2646970667358221220fb757efaa1a5b5711adfcca5d02365b7e8408bfa6624b2b9bf549a8fa2f4f1fc64736f6c63430008190033")]
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
            assembly { h := blockhash(sub(number(), 255)) }
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
);

static ANVIL_CHAIN_SPEC: Lazy<ChainSpec> =
    Lazy::new(|| ChainSpec::new_single(31337, SpecId::CANCUN, EIP1559_CONSTANTS_DEFAULT));

type TestProvider = FillProvider<
    JoinFill<RecommendedFiller, WalletFiller<EthereumWallet>>,
    AnvilProvider<RootProvider<Http<Client>>, Http<Client>>,
    Http<Client>,
    Ethereum,
>;

async fn test_provider() -> TestProvider {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_anvil_with_wallet_and_config(|anvil| anvil.args(["--hardfork", "cancun"]));
    let node_info = provider.anvil_node_info().await.unwrap();
    log::info!("Anvil started: {:?}", node_info);
    let instance = SteelTest::deploy(&provider).await.unwrap();
    assert_eq!(*instance.address(), STEEL_TEST_CONTRACT);
    provider
        .anvil_mine(Some(U256::from(254)), None)
        .await
        .unwrap();

    provider
}

#[tokio::test]
async fn precompile() {
    let result = eth_call(
        test_provider().await,
        SteelTest::testPrecompileCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::empty(),
    )
    .await;
    assert_eq!(
        result._0,
        b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

#[tokio::test]
async fn nonexistent_account() {
    let result = eth_call(
        test_provider().await,
        SteelTest::testNonexistentAccountCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::empty(),
    )
    .await;
    assert_eq!(result.size, uint!(0_U256));
}

#[tokio::test]
async fn eoa_account() {
    let result = eth_call(
        test_provider().await,
        SteelTest::testEoaAccountCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::empty(),
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
        .anvil_mine(Some(U256::from(255)), None)
        .await
        .unwrap();

    let result = eth_call(
        provider,
        SteelTest::testBlockhashCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::empty(),
    )
    .await;
    assert_eq!(result.h, block_hash);
}

#[tokio::test]
async fn chainid() {
    let result = eth_call(
        test_provider().await,
        SteelTest::testChainidCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::empty(),
    )
    .await;
    assert_eq!(result._0, uint!(31337_U256));
}

#[tokio::test]
async fn origin() {
    let from = address!("0000000000000000000000000000000000000042");
    let result = eth_call(
        test_provider().await,
        SteelTest::testOriginCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::from(from),
    )
    .await;
    assert_eq!(result._0, from);
}

#[tokio::test]
async fn gasprice() {
    let gas_price = uint!(42_U256);
    let result = eth_call(
        test_provider().await,
        SteelTest::testGaspriceCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::gas_price(gas_price),
    )
    .await;
    assert_eq!(result._0, gas_price);
}

#[test(tokio::test)]
async fn multi_contract_calls() {
    let result = eth_call(
        test_provider().await,
        SteelTest::testMuliContractCallsCall {},
        STEEL_TEST_CONTRACT,
        CallBuilderOverrides::empty(),
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

/// Simple struct to operate over different [CallBuilder] types.
#[derive(Debug, Default)]
struct CallBuilderOverrides {
    gas_price: Option<U256>,
    from: Option<Address>,
}

impl CallBuilderOverrides {
    fn empty() -> Self {
        CallBuilderOverrides::default()
    }
    fn from(from: Address) -> Self {
        Self {
            from: Some(from),
            ..Default::default()
        }
    }
    fn gas_price(gas_price: U256) -> Self {
        Self {
            gas_price: Some(gas_price),
            ..Default::default()
        }
    }

    fn set<E, C>(&self, mut builder: CallBuilder<E, C>) -> CallBuilder<E, C> {
        if let Some(gas_price) = self.gas_price {
            builder = builder.gas_price(gas_price);
        }
        if let Some(from) = self.from {
            builder = builder.from(from);
        }
        builder
    }
}

async fn eth_call<C>(
    provider: TestProvider,
    call: C,
    address: Address,
    call_overrides: CallBuilderOverrides,
) -> C::Return
where
    C: SolCall + Send + 'static,
    <C as SolCall>::Return: PartialEq + Debug + Send,
{
    let mut env = EthEvmEnv::from_provider(provider, BlockNumberOrTag::Latest)
        .await
        .unwrap()
        .with_chain_spec(&ANVIL_CHAIN_SPEC);
    let block_hash = env.header().hash_slow();
    let block_number = U256::from(env.header().number());

    let mut preflight = Contract::preflight(address, &mut env);
    let preflight_result = call_overrides
        .set(preflight.call_builder(&call))
        .call()
        .await
        .unwrap();

    let input = env.into_input().await.unwrap();

    let env = input.into_env().with_chain_spec(&ANVIL_CHAIN_SPEC);
    let commitment = env.block_commitment();
    assert_eq!(commitment.blockHash, block_hash, "invalid commitment");
    assert_eq!(commitment.blockNumber, block_number, "invalid commitment");

    let contract = Contract::new(address, &env);
    let result = call_overrides.set(contract.call_builder(&call)).call();
    assert_eq!(
        result, preflight_result,
        "mismatch in preflight and execution"
    );

    result
}
