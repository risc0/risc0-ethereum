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

use std::{fs::File, path::PathBuf};

use alloy::{
    network::{Ethereum, EthereumWallet},
    providers::{PendingTransactionBuilder, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
    transports::Transport,
};
use alloy_primitives::{Address, Bytes, TxHash};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use cross_domain_messenger_core::{CrossDomainMessengerInput, IL1CrossDomainMessenger, Message};
use cross_domain_messenger_methods::CROSS_DOMAIN_MESSENGER_ELF;
use risc0_ethereum_contracts::encode_seal;
use risc0_steel::{ethereum::EthEvmEnv, Contract};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::{
    task,
    time::{sleep, Duration},
};
use tracing_subscriber::EnvFilter;
use url::Url;

/// Simple program to create the Risc Zero proof that a message to be passed to L2 was sent on L1
#[derive(Parser)]
struct Args {
    /// L2 private key.
    #[clap(long, env)]
    l2_wallet_private_key: PrivateKeySigner,

    /// L1 RPC node endpoint.
    #[clap(long, env)]
    l1_rpc_url: Url,

    /// L2 RPC node endpoint.
    #[clap(long, env)]
    l2_rpc_url: Url,

    /// L1CrossDomainMessenger's contract address on L1
    #[clap(long, env)]
    l1_cross_domain_messenger_address: Address,

    /// L2CrossDomainMessenger's contract address on L2
    #[clap(long, env)]
    l2_cross_domain_messenger_address: Address,

    /// Hash of the transaction calling 'L1CrossDomainMessenger.sendMessage(...)'
    #[clap(long)]
    tx_hash: TxHash,

    /// Path of the output JSON file with the generated proof
    #[clap(long, short, default_value = "proof.json")]
    output: PathBuf,
}

alloy::sol!(
    #[sol(rpc, all_derives)]
    "../../contracts/src/IBookmark.sol"
);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    dotenvy::dotenv()?;
    let args = Args::try_parse()?;

    let l1_provider = ProviderBuilder::new().on_http(args.l1_rpc_url);

    // Try to extract the sent message for the given tx hash.
    let receipt = l1_provider
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
    log::info!("Transaction emitted {:?}", log.data());
    let message: Message = log.inner.data.into();

    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.l2_wallet_private_key);
    let l2_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.l2_rpc_url);

    // Wait until a block containing the message can be bookmarked on L2.
    let bookmark_instance = IBookmark::new(args.l2_cross_domain_messenger_address, l2_provider);
    let bookmark_call = bookmark_instance.bookmarkL1Block();
    loop {
        let l2_l1_block_number = bookmark_call
            .call()
            .await
            .with_context(|| format!("eth_call failed: {:?}", bookmark_call))?
            ._0;
        if l2_l1_block_number >= message_block_number {
            break;
        }
        log::info!(
            "Waiting for L2 to catch up: {} < {}",
            l2_l1_block_number,
            message_block_number
        );
        sleep(Duration::from_secs(12)).await;
    }

    log::info!("Bookmarking the current L1 block hash on L2");
    let pending_tx = bookmark_call
        .send()
        .await
        .with_context(|| format!("eth_sendTransaction failed: {:?}", bookmark_call))?;
    let bookmarked_l1_block = confirm_tx::<_, IBookmark::BookmarkedL1Block>(pending_tx).await?;
    log::info!("{:?}", &bookmarked_l1_block);

    // Create an EVM environment from the L1 provider and the bookmarked block.
    let mut env = EthEvmEnv::builder()
        .provider(l1_provider)
        .block_number(bookmarked_l1_block.number)
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
    assert!(success, "preflight returned 'false'");

    // Finally, construct the input for the guest.
    let evm_input = env
        .into_input()
        .await
        .context("failed to crate steel input")?;
    let cross_domain_messenger_input = CrossDomainMessengerInput {
        l1_cross_domain_messenger: args.l1_cross_domain_messenger_address,
        message,
    };

    // Create the steel proof.
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

async fn confirm_tx<T: Transport + Clone, E: SolEvent>(
    pending_tx: PendingTransactionBuilder<'_, T, Ethereum>,
) -> Result<E> {
    let tx_hash = pending_tx.tx_hash().clone();
    let receipt = pending_tx
        .with_timeout(Some(Duration::from_secs(30)))
        .get_receipt()
        .await
        .with_context(|| format!("transaction did not confirm: {}", tx_hash))?;
    let log = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| log.log_decode::<E>().ok())
        .with_context(|| format!("event not emitted: {}", E::SIGNATURE))?;
    Ok(log.inner.data)
}
