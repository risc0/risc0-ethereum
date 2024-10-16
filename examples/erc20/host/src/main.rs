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

use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolCall, SolType};
use anyhow::{Context, Result};
use clap::Parser;
use erc20_methods::ERC20_GUEST_ELF;
use risc0_steel::{
    ethereum::{EthEvmEnv, ETH_SEPOLIA_CHAIN_SPEC},
    Commitment, Contract,
};
use risc0_zkvm::{default_executor, ExecutorEnv};
use tracing_subscriber::EnvFilter;
use url::Url;

sol! {
    /// ERC-20 balance function signature.
    /// This must match the signature in the guest.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

/// Function to call, implements the [SolCall] trait.
const CALL: IERC20::balanceOfCall = IERC20::balanceOfCall {
    account: address!("9737100D2F42a196DE56ED0d1f6fF598a250E7E4"),
};

/// Address of the deployed contract to call the function on (USDT contract on Sepolia).
const CONTRACT: Address = address!("aA8E23Fb1079EA71e0a56F48a2aA51851D8433D0");
/// Address of the caller.
const CALLER: Address = address!("f08A50178dfcDe18524640EA6618a1f965821715");

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
    let mut env = EthEvmEnv::builder().rpc(args.rpc_url).build().await?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(CONTRACT, &mut env);
    let returns = contract.call_builder(&CALL).from(CALLER).call().await?;
    println!(
        "Call {} Function by {:#} on {:#} returns: {}",
        IERC20::balanceOfCall::SIGNATURE,
        CALLER,
        CONTRACT,
        returns._0
    );

    // Finally, construct the input from the environment.
    let input = env.into_input().await?;

    println!("Running the guest with the constructed input...");
    let session_info = {
        let env = ExecutorEnv::builder()
            .write(&input)
            .unwrap()
            .build()
            .context("failed to build executor env")?;
        let exec = default_executor();
        exec.execute(env, ERC20_GUEST_ELF)
            .context("failed to run executor")?
    };

    // The journal should be the ABI encoded commitment.
    let commitment = Commitment::abi_decode(session_info.journal.as_ref(), true)
        .context("failed to decode journal")?;
    println!("{:?}", commitment);

    Ok(())
}
