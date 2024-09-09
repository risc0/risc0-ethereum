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

use alloy::providers::{Provider, ProviderBuilder};
use alloy_primitives::{Address, TxHash};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use cross_domain_messenger_core::{CrossDomainMessengerInput, IL1CrossDomainMessenger, Message};
use cross_domain_messenger_methods::CROSS_DOMAIN_MESSENGER_ELF;
use risc0_ethereum_contracts::encode_seal;
use risc0_steel::{ethereum::EthEvmEnv, Contract};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

/// Arguments of the publisher CLI.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// RPC node endpoint.
    #[clap(long, env)]
    rpc_url: Url,

    /// Beacon API endpoint URL.
    #[clap(long, env)]
    beacon_api_url: Url,

    /// l1_cross_domain_messenger_address's contract address on L1
    #[clap(long, env)]
    cross_domain_messenger_address: Address,

    /// Hash of the IL1CrossDomainMessenger::sendMessage() transaction
    #[clap(long)]
    tx_hash: TxHash,
}

alloy::sol!("../../contracts/src/IL2CrossDomainMessenger.sol");

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    dotenvy::dotenv()?;
    let args = Args::try_parse()?;

    let provider = ProviderBuilder::new().on_http(args.rpc_url);

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
        .filter(|log| log.address() == args.cross_domain_messenger_address)
        .find_map(|log| {
            log.log_decode::<IL1CrossDomainMessenger::SentMessage>()
                .ok()
        })
        .context("tx invalid")?;
    let message: Message = log.inner.data.into();

    // Create an EVM environment from that provider and a block number.
    let mut env = EthEvmEnv::builder()
        .provider(provider)
        .block_number(message_block_number)
        .build()
        .await?;
    // Prepare the function call to be called inside steal
    let call = IL1CrossDomainMessenger::containsCall {
        digest: message.digest(),
    };
    // Preflight the call to prepare the input for the guest.
    let mut contract = Contract::preflight(args.cross_domain_messenger_address, &mut env);
    let success = contract.call_builder(&call).call().await?._0;
    assert!(success, "message {} not found", call.digest);

    // Finally, construct the input for the guest.
    let evm_input = env.into_beacon_input(args.beacon_api_url).await?;
    let cross_domain_messenger_input = CrossDomainMessengerInput {
        l1_cross_domain_messenger: args.cross_domain_messenger_address,
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
    .await??;
    let receipt = prove_info.receipt;

    // Encode the groth16 seal with the selector.
    let seal = encode_seal(&receipt)?;

    let call = IL2CrossDomainMessenger::relayMessageCall {
        journal: receipt.journal.bytes.into(),
        seal: seal.into(),
    };
    println!("{} {}", call.journal, call.seal);

    Ok(())
}
