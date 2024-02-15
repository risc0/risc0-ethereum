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

use std::{io::Write, time::Duration};

use alloy_primitives::FixedBytes;
use anyhow::{Context, Result};
use bonsai_sdk::alpha as bonsai_sdk;
use clap::Parser;
use ethers::abi::Token;
use risc0_ethereum_contracts::groth16::Seal;
use risc0_zkvm::{compute_image_id, default_executor, is_dev_mode, ExecutorEnv, Receipt};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
enum Command {
    /// Prove the RISC-V ELF binary.
    Prove {
        /// The guest binary path
        guest_binary_path: String,

        /// The hex encoded input to provide to the guest binary
        input: String,
    },
}

/// Run the CLI.
pub fn main() -> Result<()> {
    match Command::parse() {
        Command::Prove {
            guest_binary_path,
            input,
        } => prove_ffi(
            guest_binary_path,
            hex::decode(input.strip_prefix("0x").unwrap_or(&input))?,
        )?,
    };

    Ok(())
}

/// Prints on stdio the Ethereum ABI and hex encoded proof.
fn prove_ffi(elf_path: String, input: Vec<u8>) -> Result<()> {
    let elf = std::fs::read(elf_path).unwrap();
    let (journal, post_state_digest, seal) = prove(&elf, &input)?;
    let calldata = vec![
        Token::Bytes(journal),
        Token::FixedBytes(post_state_digest.to_vec()),
        Token::Bytes(seal),
    ];
    let output = hex::encode(ethers::abi::encode(&calldata));

    // Forge test FFI calls expect hex encoded bytes sent to stdout
    print!("{output}");
    std::io::stdout()
        .flush()
        .context("failed to flush stdout buffer")?;
    Ok(())
}

/// Generates a snark proof as a triplet (`Vec<u8>`, `FixedBytes<32>`, `Vec<u8>)
/// for the given elf and input.
/// When `RISC0_DEV_MODE` is set, executes the elf locally,
/// as opposed to sending the proof request to the Bonsai service.
fn prove(elf: &[u8], input: &[u8]) -> Result<(Vec<u8>, FixedBytes<32>, Vec<u8>)> {
    match is_dev_mode() {
        true => DevModeProver::prove(elf, input),
        false => BonsaiProver::prove(elf, input),
    }
}

trait Prover {
    fn prove(elf: &[u8], input: &[u8]) -> Result<(Vec<u8>, FixedBytes<32>, Vec<u8>)>;
}

struct DevModeProver {}

impl DevModeProver {
    fn prove(elf: &[u8], input: &[u8]) -> Result<(Vec<u8>, FixedBytes<32>, Vec<u8>)> {
        let env = ExecutorEnv::builder()
            .write_slice(input)
            .build()
            .context("Failed to build exec env")?;
        let exec = default_executor();
        let session_info = exec.execute(env, elf).context("Failed to run executor")?;

        Ok((
            session_info.journal.bytes,
            FixedBytes::<32>::default(),
            Vec::new(),
        ))
    }
}

struct BonsaiProver {}
impl BonsaiProver {
    fn prove(elf: &[u8], input: &[u8]) -> Result<(Vec<u8>, FixedBytes<32>, Vec<u8>)> {
        let client = bonsai_sdk::Client::from_env(risc0_zkvm::VERSION)?;

        // Compute the image_id, then upload the ELF with the image_id as its key.
        let image_id = compute_image_id(elf)?;
        let image_id_hex = image_id.to_string();
        client.upload_img(&image_id_hex, elf.to_vec())?;
        log::info!("Image ID: 0x{}", image_id_hex);

        // Prepare input data and upload it.
        let input_id = client.upload_input(input.to_vec())?;

        // Start a session running the prover.
        let session = client.create_session(image_id_hex, input_id, vec![])?;
        log::info!("Created session: {}", session.uuid);
        let _receipt = loop {
            let res = session.status(&client)?;
            if res.status == "RUNNING" {
                log::info!(
                    "Current status: {} - state: {} - continue polling...",
                    res.status,
                    res.state.unwrap_or_default()
                );
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
            if res.status == "SUCCEEDED" {
                // Download the receipt, containing the output.
                let receipt_url = res
                    .receipt_url
                    .context("API error, missing receipt on completed session")?;

                let receipt_buf = client.download(&receipt_url)?;
                let receipt: Receipt = bincode::deserialize(&receipt_buf)?;

                break receipt;
            } else {
                panic!(
                    "Workflow exited: {} - | err: {}",
                    res.status,
                    res.error_msg.unwrap_or_default()
                );
            }
        };

        // Fetch the snark.
        let snark_session = client.create_snark(session.uuid)?;
        log::info!("Created snark session: {}", snark_session.uuid);
        let snark_receipt = loop {
            let res = snark_session.status(&client)?;
            match res.status.as_str() {
                "RUNNING" => {
                    log::info!("Current status: {} - continue polling...", res.status,);
                    std::thread::sleep(Duration::from_secs(15));
                    continue;
                }
                "SUCCEEDED" => {
                    break res.output.context("No snark generated :(")?;
                }
                _ => {
                    panic!(
                        "Workflow exited: {} err: {}",
                        res.status,
                        res.error_msg.unwrap_or_default()
                    );
                }
            }
        };

        let snark = snark_receipt.snark;
        log::debug!("Snark proof!: {snark:?}");

        let seal = Seal::abi_encode(snark).context("Read seal")?;
        let post_state_digest: FixedBytes<32> = snark_receipt
            .post_state_digest
            .as_slice()
            .try_into()
            .context("Read post_state_digest")?;
        let journal = snark_receipt.journal;

        Ok((journal, post_state_digest, seal))
    }
}
