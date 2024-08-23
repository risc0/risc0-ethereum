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

use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner, sol,
    sol_types::SolCall,
};
use alloy_primitives::Address;
use anyhow::{ensure, Context, Result};
use clap::Parser;
use cross_domain_messenger_core::{
    contracts::{
        IBookmarkService, IL1CrossDomainMessenger, IL1CrossDomainMessengerService,
        IL2CrossDomainMessengerService,
    },
    CrossDomainMessengerInput,
};
use cross_domain_messenger_methods::CROSS_DOMAIN_MESSENGER_ELF;
use risc0_ethereum_contracts::encode_seal;
use risc0_steel::{ethereum::EthEvmEnv, Contract};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

// Contract to call via L1.
sol!("../contracts/src/ICounter.sol");

/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// L1 private key.
    #[clap(long, env)]
    l1_wallet_private_key: PrivateKeySigner,

    /// L2 private key.
    #[clap(long, env)]
    l2_wallet_private_key: PrivateKeySigner,

    /// L1 RPC node endpoint.
    #[clap(long, env)]
    l1_rpc_url: Url,

    /// L2 RPC node endpoint.
    #[clap(long, env)]
    l2_rpc_url: Url,

    /// Target's contract address on L2
    #[clap(long, env)]
    counter_address: Address,

    /// l1_cross_domain_messenger_address's contract address on L1
    #[clap(long, env)]
    l1_cross_domain_messenger_address: Address,

    /// l2_cross_domain_messenger_address's contract address on L2
    #[clap(long, env)]
    l2_cross_domain_messenger_address: Address,
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
    let wallet = EthereumWallet::from(args.l1_wallet_private_key);
    let l1_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.l1_rpc_url);

    let wallet = EthereumWallet::from(args.l2_wallet_private_key);
    let l2_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.l2_rpc_url);

    // Instantiate all the contracts we want to call.
    let l1_messenger_contract = IL1CrossDomainMessengerService::new(
        args.l1_cross_domain_messenger_address,
        l1_provider.clone(),
    );
    let l2_messenger_contract = IL2CrossDomainMessengerService::new(
        args.l2_cross_domain_messenger_address,
        l2_provider.clone(),
    );
    let bookmark_contract =
        IBookmarkService::new(args.l2_cross_domain_messenger_address, l2_provider.clone());

    // Prepare the message to be passed from L1 to L2
    let target = args.counter_address;
    let data = ICounter::incrementCall {}.abi_encode();

    // Send a transaction calling IL1CrossDomainMessenger.sendMessage
    let (message, message_block_number) = l1_messenger_contract
        .send_message(target, data.into())
        .await?;

    // Bookmark the block number of the message
    let bookmark_block_number = bookmark_contract.bookmark(message_block_number).await?;

    // Run Steel:
    // Create an EVM environment from that provider and a block number.
    let mut env =
        EthEvmEnv::from_provider(l1_provider.clone(), bookmark_block_number.into()).await?;
    // Prepare the function call to be called inside steal
    let call = IL1CrossDomainMessenger::containsCall {
        digest: message.digest(),
    };
    // Preflight the call to prepare the input for the guest.
    let mut contract = Contract::preflight(args.l1_cross_domain_messenger_address, &mut env);
    let success = contract.call_builder(&call).call().await?._0;
    ensure!(success, "message {} not found", call.digest);
    // Finally, construct the input for the guest.
    let evm_input = env.into_input().await?;
    let cross_domain_messenger_input = CrossDomainMessengerInput {
        l1_cross_domain_messenger: args.l1_cross_domain_messenger_address,
        message,
    };

    println!("Creating proof for the constructed input...");
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&cross_domain_messenger_input)?
            .build()
            .unwrap();

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            CROSS_DOMAIN_MESSENGER_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;
    println!(
        "Proving finished in {} cycles",
        prove_info.stats.total_cycles
    );
    let receipt = prove_info.receipt;

    // Encode the groth16 seal with the selector.
    let seal = encode_seal(&receipt)?;

    // Call the increment function of the contract and wait for confirmation.
    let msg_hash = l2_messenger_contract
        .relay_message(receipt.journal.bytes.into(), seal.into())
        .await?;
    println!("Message relayed {:?}", msg_hash);

    Ok(())
}
