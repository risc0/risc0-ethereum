// Copyright 2025 RISC Zero, Inc.
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

use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolEvent, SolValue};
use anyhow::{Context, Result};
use clap::Parser;
use events_methods::EVENTS_GUEST_ELF;
use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_SEPOLIA_CHAIN_SPEC},
    Commitment, Event,
};
use risc0_zkvm::{default_executor, ExecutorEnv};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

sol! {
    /// ERC-20 transfer event signature.
    /// This must match the signature in the guest.
    #[derive(Debug)]
    interface IERC20 {
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
}

/// Address of the deployed contract to call the function on (USDT contract on Mainnet).
const CONTRACT: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");

sol! {
    /// ABI-encodable journal.
    struct Journal {
        Commitment commitment;
        bytes32 blockHash;
        uint256 value;
    }
}

/// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(short, long, env = "RPC_URL")]
    rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // Create an EVM environment from an RPC endpoint defaulting to the latest block.
    let mut env = EthEvmEnv::builder()
        .rpc(args.rpc_url)
        .chain_spec(&ETH_SEPOLIA_CHAIN_SPEC)
        .build()
        .await?;

    // Preflight the event query to prepare the input that is required to execute the function in
    // the guest without RPC access.
    let event = Event::preflight::<IERC20::Transfer>(&mut env);
    let logs = event.address(CONTRACT).query().await?;
    log::info!(
        "Contract {} emitted {} events with signature: {}",
        CONTRACT,
        logs.len(),
        IERC20::Transfer::SIGNATURE,
    );

    // Finally, construct the input from the environment.
    let evm_input = env.into_input().await?;

    let session_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write(&evm_input)
            .context("failed to encode input")?
            .build()
            .context("failed to build env")?;
        let exec = default_executor();
        exec.execute(env, EVENTS_GUEST_ELF)
            .context("failed to run executor")
    })
    .await?
    .context("failed to execute guest")?;

    // The journal should be the ABI encoded commitment.
    let journal =
        Journal::abi_decode(session_info.journal.as_ref()).context("failed to decode journal")?;
    log::debug!("Steel commitment: {:?}", journal.commitment);

    log::info!(
        "Total USDT transferred in block {}: {}",
        journal.blockHash,
        journal.value,
    );

    Ok(())
}
