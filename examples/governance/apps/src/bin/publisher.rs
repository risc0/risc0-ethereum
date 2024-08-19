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

use alloy_sol_types::{sol, SolInterface};
use anyhow::{Context, Result};
use clap::Parser;
use ethers::prelude::*;
use hex::decode;
use methods::FINALIZE_VOTES_ELF;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

sol! {
    interface RiscZeroGovernor {
        function verifyAndFinalizeVotes(bytes calldata seal, bytes calldata journal) public;
    }
}

/// Wrapper of a `SignerMiddleware` client to send transactions to the given
/// contract's `Address`.
pub struct TxSender {
    chain_id: u64,
    client: SignerMiddleware<Provider<Http>, Wallet<k256::ecdsa::SigningKey>>,
    contract: Address,
}

impl TxSender {
    /// Creates a new `TxSender`.
    pub fn new(chain_id: u64, rpc_url: &str, private_key: &str, contract: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet: LocalWallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id);
        let client = SignerMiddleware::new(provider.clone(), wallet.clone());
        let contract = contract.parse::<Address>()?;

        Ok(TxSender {
            chain_id,
            client,
            contract,
        })
    }

    /// Send a transaction with the given calldata.
    pub async fn send(&self, calldata: Vec<u8>) -> Result<Option<TransactionReceipt>> {
        let tx = TransactionRequest::new()
            .chain_id(self.chain_id)
            .to(self.contract)
            .from(self.client.address())
            .data(calldata);

        log::info!("Transaction request: {:?}", &tx);

        let tx = self.client.send_transaction(tx, None).await?.await?;

        log::info!("Transaction receipt: {:?}", &tx);

        Ok(tx)
    }
}

/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Ethereum chain ID
    #[clap(long)]
    chain_id: u64,

    /// Ethereum Wallet Private Key
    #[clap(long, env)]
    eth_wallet_private_key: String,

    /// Node RPC URL
    #[clap(long)]
    rpc_url: String,

    /// Application's contract address on Ethereum
    #[clap(long)]
    contract: String,

    /// The proposal ID (32 bytes, hex-encoded)
    #[clap(long)]
    proposal_id: String,

    /// The votes data (hex-encoded, multiple of 100 bytes)
    #[clap(long)]
    votes_data: String,
}

fn main() -> Result<()> {
    env_logger::init();
    // Parse CLI Arguments: The application starts by parsing command-line arguments provided by the user.
    let args = Args::parse();

    // Create a new transaction sender using the parsed arguments.
    let tx_sender = TxSender::new(
        args.chain_id,
        &args.rpc_url,
        &args.eth_wallet_private_key,
        &args.contract,
    )?;

    // Decode the hex-encoded proposal ID and votes data
    let proposal_id = decode(&args.proposal_id).context("Failed to decode proposal ID")?;
    let votes_data = decode(&args.votes_data).context("Failed to decode votes data")?;

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

    // Compute the ImageID of `finalize_votes.rs` ELF binary.
    // let image_id = compute_image_id(FINALIZE_VOTES_ELF)?;
    // let image_id_bytes: [u8; 32] = image_id
    //     .as_bytes()
    //     .try_into()
    //     .expect("Digest should be 32 bytes");
    // let image_id_fixed_bytes = FixedBytes::<32>::from(image_id_bytes);

    // Encode the seal with the selector.
    let seal = risc0_ethereum_contracts::encode_seal(&receipt)?;

    // Extract the journal from the receipt.
    let journal = receipt.journal.bytes.clone();

    // Construct function call for RiscZeroGovernor
    let calldata = RiscZeroGovernor::RiscZeroGovernorCalls::verifyAndFinalizeVotes(
        RiscZeroGovernor::verifyAndFinalizeVotesCall {
            seal: seal.into(),
            journal: journal,
        },
    )
    .abi_encode();

    // Initialize the async runtime environment to handle the transaction sending.
    let runtime = tokio::runtime::Runtime::new()?;

    // Send transaction: Finally, the TxSender component sends the transaction to the Ethereum blockchain,
    // effectively calling the set function of the EvenNumber contract with the verified number and proof.
    runtime.block_on(tx_sender.send(calldata))?;

    Ok(())
}
