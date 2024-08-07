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

// This application demonstrates how to send an off-chain proof request
// to the Bonsai proving service and publish the received proofs directly
// to your deployed app contract.

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol_types::{SolCall, SolValue},
};
use alloy_primitives::Address;
use anyhow::{ensure, Context, Result};
use beacon_root_methods::{BALANCE_OF_ELF, BALANCE_OF_ID};
use clap::Parser;
use risc0_ethereum_contracts::encode_seal;
use risc0_steel::{
    ethereum::{EthEvmBeaconInput, EthEvmEnv, ETH_SEPOLIA_CHAIN_SPEC},
    host::BlockNumberOrTag,
    Contract, SolCommitment,
};
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

alloy::sol! {
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

alloy::sol! {
    struct Journal {
        SolCommitment commitment;
        address tokenContract;
    }
}

alloy::sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/ICounter.sol"
);

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Private key.
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum RPC endpoint URL.
    #[clap(long, env)]
    eth_rpc_url: Url,

    /// Beacon API endpoint URL.
    #[clap(long, env)]
    beacon_api_url: Url,

    /// Address of the Counter verifier.
    #[clap(long)]
    counter: Address,

    /// Address of the ERC20 token contract.
    #[clap(long, env)]
    token_contract: Address,

    /// Address to query the token balance of.
    #[clap(long)]
    account: Address,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    dotenvy::dotenv()?;
    let args = Args::try_parse()?;

    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.eth_rpc_url);

    // Create an EVM environment from that provider and a block number.
    let mut env = EthEvmEnv::from_provider(provider.clone(), BlockNumberOrTag::Latest).await?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

    // Prepare the function call
    let call = IERC20::balanceOfCall {
        account: args.account,
    };

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(args.token_contract, &mut env);
    let returns = contract.call_builder(&call).call().await?;
    println!(
        "Call {} Function on {:#} returns: {}",
        IERC20::balanceOfCall::SIGNATURE,
        args.token_contract,
        returns._0
    );

    // Finally, construct the input from the environment.
    let evm_input = env.into_input().await?;
    let evm_input =
        EthEvmBeaconInput::from_endpoint_and_input(args.beacon_api_url, evm_input).await?;

    println!("Creating proof for the constructed input...");
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&args.token_contract)?
            .write(&args.account)?
            .build()
            .unwrap();

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            BALANCE_OF_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;
    let receipt = prove_info.receipt;
    let journal = &receipt.journal.bytes;

    // Validate the commitment
    let journal = Journal::abi_decode(journal, true).context("invalid journal")?;
    println!(
        "The guest committed to Beacon block {} at timestamp {}",
        journal.commitment.blockHash, journal.commitment.blockNumber
    );

    // ABI encode the seal.
    let seal = encode_seal(&receipt)?;

    // Create an alloy instance of the Counter contract.
    let contract = ICounter::new(args.counter, provider);

    // Call ICounter::imageID() to check that the contract has been deployed correctly.
    let contract_image_id = Digest::from(contract.imageId().call().await?._0.0);
    ensure!(contract_image_id == Digest::from(BALANCE_OF_ID));

    // Call the increment function of the contract and wait for confirmation.
    println!(
        "Sending Tx calling {} Function of {:#}...",
        ICounter::incrementCall::SIGNATURE,
        contract.address()
    );
    let call_builder = contract.increment(receipt.journal.bytes.into(), seal.into());
    log::debug!("Send {} {}", contract.address(), call_builder.calldata());
    let pending_tx = call_builder.send().await?;
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(60)))
        .get_receipt()
        .await?;
    ensure!(receipt.status(), "transaction failed");

    let value = contract.counter().call().await?._0;
    println!("New value of Counter: {}", value);

    Ok(())
}
