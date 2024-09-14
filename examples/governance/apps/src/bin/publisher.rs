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

use anyhow::{Context, Result};
use clap::Parser;

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    // sol_types::SolInterface
};

use governance_methods::FINALIZE_VOTES_ELF;
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
// use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

sol! {
    /// ERC-20 balance function signature.
    /// This must match the signature in the guest.
    interface RiscZeroGovernor {
        function verifyAndFinalizeVotes(bytes calldata seal, bytes calldata journal) public;
    }
}

/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Ethereum Wallet Private Key
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Node RPC URL
    #[clap(long)]
    rpc_url: Url,

    /// Application's contract address on Ethereum
    #[clap(long)]
    contract: Address,

    /// The proposal ID (32 bytes, hex-encoded)
    #[clap(long)]
    proposal_id: Bytes,

    /// The votes data (hex-encoded, multiple of 100 bytes)
    #[clap(long)]
    votes_data: Bytes,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.rpc_url);

    // Decode the hex-encoded proposal ID and votes data
    let proposal_id = hex::decode(&args.proposal_id).context("Failed to decode proposal ID")?;
    let votes_data = hex::decode(&args.votes_data).context("Failed to decode votes data")?;

    // Validate input lengths
    if proposal_id.len() != 32 {
        return Err(anyhow::anyhow!("Proposal ID must be 32 bytes"));
    }
    if votes_data.len() % 100 != 0 {
        return Err(anyhow::anyhow!(
            "Votes data must be a multiple of 100 bytes"
        ));
    }

    // Combine proposal ID and votes data
    let input = [&proposal_id[..], &votes_data[..]].concat();

    let env = ExecutorEnv::builder().write_slice(&input).build()?;

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            FINALIZE_VOTES_ELF,
            &ProverOpts::groth16(),
        )?
        .receipt;

    // Encode the seal with the selector.
    let seal = encode_seal(&receipt)?;

    // Extract the journal from the receipt.
    let journal = receipt.journal.bytes.clone();

    // build calldata
    let calldata = RiscZeroGovernor::verifyAndFinalizeVotesCall {
        seal: seal.into(),
        journal: journal.into(),
    };

    // send tx to callback function: verifyAndFinalizeVotes
    let contract = args.contract;
    let tx = TransactionRequest::default()
        .with_to(contract)
        .with_call(&calldata);
    let tx_hash = provider
        .send_transaction(tx)
        .await
        .context("Failed to send transaction")?;
    println!("Transaction sent with hash: {:?}", tx_hash);

    Ok(())
}
