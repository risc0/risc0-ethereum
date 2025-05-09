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

use alloy::{
    primitives::{address, Address},
    sol_types::SolCall,
};
use anyhow::{Context, Result};
use clap::Parser;
use l2_to_l1_core::{CALL, CALLER, CONTRACT, IERC20};
use l2_to_l1_methods::{L2_TO_L1_GUEST_ELF, L2_TO_L1_GUEST_ID};
use risc0_op_steel::{
    optimism::{OpEvmEnv, OP_MAINNET_CHAIN_SPEC},
    Contract, DisputeGameIndex,
};
use risc0_zkvm::{default_prover, Digest, ExecutorEnv, ProverOpts, VerifierContext};
use tokio::task;
use tracing_subscriber::EnvFilter;
use url::Url;

/// Address of the OptimismPortalProxy on L1 for OP Mainnet.
const OPTIMISM_PORTAL: Address = address!("bEb5Fc579115071764c7423A4f12eDde41f106Ed");

/// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the L1 OP RPC endpoint
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: Url,

    /// URL of the L2 OP RPC endpoint
    #[arg(long, env = "L2_RPC_URL")]
    l2_rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    // Build an environment based on the state of the latest finalized fault dispute game
    let builder = OpEvmEnv::builder()
        .dispute_game_from_rpc(OPTIMISM_PORTAL, args.l1_rpc_url.clone())
        .game_index(DisputeGameIndex::Finalized);
    let mut env = builder
        .rpc(args.l2_rpc_url)
        .chain_spec(&OP_MAINNET_CHAIN_SPEC)
        .build()
        .await?;

    let mut contract = Contract::preflight(CONTRACT, &mut env);
    let mut builder = contract.call_builder(&CALL);
    builder.tx.base.caller = CALLER;
    let returns = builder.call().await?;
    log::info!(
        "Call {} Function by {:#} on {:#} returns: {}",
        IERC20::balanceOfCall::SIGNATURE,
        CALLER,
        CONTRACT,
        returns
    );
    log::debug!("{:?}", env.commitment());

    let evm_input = env.into_input().await?;

    let image_id: Digest = L2_TO_L1_GUEST_ID.into();
    let prove_info = task::spawn_blocking(move || {
        let env = ExecutorEnv::builder().write(&evm_input)?.build().unwrap();

        default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            L2_TO_L1_GUEST_ELF,
            &ProverOpts::groth16(),
        )
    })
    .await?
    .context("failed to create proof")?;
    log::debug!("Finished proving {}: {:?}", image_id, prove_info.stats);

    #[cfg(feature = "verify")]
    examples_common::verify_on_chain(prove_info.receipt, image_id, args.l1_rpc_url).await?;

    Ok(())
}
