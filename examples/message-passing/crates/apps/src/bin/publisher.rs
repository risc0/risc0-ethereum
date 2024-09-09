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

use alloy::sol_types::SolCall;
use alloy::providers::{Provider, ProviderBuilder};
use alloy_primitives::{Address, Bytes, TxHash};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use cross_domain_messenger_core::{CrossDomainMessengerInput, IL1CrossDomainMessenger, Message};
use cross_domain_messenger_methods::CROSS_DOMAIN_MESSENGER_ELF;
use risc0_ethereum_contracts::encode_seal;
use risc0_steel::{ethereum::EthEvmEnv, Contract};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use std::fs::File;
use std::path::PathBuf;
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

/// Simple program to create the Risc Zero proof that a message to be passed to L2 was sent on L1
#[derive(Parser)]
struct Args {
    /// L1 RPC node endpoint
    #[clap(long, env)]
    l1_rpc_url: Url,

    /// Beacon API endpoint URL
    #[clap(long, env)]
    beacon_api_url: Url,

    /// L1CrossDomainMessenger's contract address on L1
    #[clap(long, env)]
    l1_cross_domain_messenger_address: Address,

    /// Hash of the transaction calling 'L1CrossDomainMessenger.sendMessage(...)'
    #[clap(long)]
    tx_hash: TxHash,

    /// Path of the output JSON file with the generated proof
    #[clap(long, short, default_value = "proof.json")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    dotenvy::dotenv()?;
    let args = Args::try_parse()?;

    let provider = ProviderBuilder::new().on_http(args.l1_rpc_url);

    // Try to extract the sent message for the given tx hash.
    let receipt = provider
        .get_transaction_receipt(args.tx_hash)
        .await?
        .context("tx pending or unknown")?;
    ensure!(receipt.status(), "tx failed");
    let message_block_number = receipt.block_number.context("tx pending")?;
    let log = receipt
        .inner
        .logs()
        .iter()
        .filter(|log| log.address() == args.l1_cross_domain_messenger_address)
        .find_map(|log| {
            log.log_decode::<IL1CrossDomainMessenger::SentMessage>()
                .ok()
        })
        .context("tx invalid")?;
    log::info!("tx emitted {:?}", log.data());
    let message: Message = log.inner.data.into();

    // Create an EVM environment from that provider and a block number.
    let mut env = EthEvmEnv::builder()
        .provider(provider)
        .block_number(message_block_number)
        .build()
        .await
        .context("failed to create steel env")?;
    // Preflight the call to prepare the input for the guest.
    let mut contract = Contract::preflight(args.l1_cross_domain_messenger_address, &mut env);
    let success = contract
        .call_builder(&IL1CrossDomainMessenger::containsCall {
            digest: message.digest(),
        })
        .call()
        .await
        .context("steel preflight failed")?
        ._0;
    assert!(
        success,
        "{} returned 'false'",
        IL1CrossDomainMessenger::containsCall::SIGNATURE
    );

    // Finally, construct the input for the guest.
    let evm_input = env
        .into_beacon_input(args.beacon_api_url)
        .await
        .context("failed to crate steel input")?;
    let cross_domain_messenger_input = CrossDomainMessengerInput {
        l1_cross_domain_messenger: args.l1_cross_domain_messenger_address,
        message,
    };

    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)?
            .write(&cross_domain_messenger_input)?
            .build()?;

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            CROSS_DOMAIN_MESSENGER_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;
    let receipt = prove_info.receipt;

    let seal = encode_seal(&receipt).context("invalid receipt")?;
    let proof = serde_json::json!({
        "seal": Bytes::from(seal),
        "journal": Bytes::from(receipt.journal.bytes),
    });

    // Create a file and write the JSON string to it.
    let file = File::create(args.output).context("failed to create output file")?;
    serde_json::to_writer_pretty(file, &proof).context("failed to write output")?;

    Ok(())
}
