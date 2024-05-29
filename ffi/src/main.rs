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

use std::io::Write;

use anyhow::{Context, Result};
use clap::Parser;
use ethers::abi::Token;
use risc0_ethereum_contracts::groth16::encode;
use risc0_zkvm::{
    default_prover, is_dev_mode, sha::Digestible, ExecutorEnv, ProverOpts, VerifierContext,
};

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
    let (journal, seal) = prove(&elf, &input)?;
    let calldata = vec![Token::Bytes(journal), Token::Bytes(seal)];
    let output = hex::encode(ethers::abi::encode(&calldata));

    // Forge test FFI calls expect hex encoded bytes sent to stdout
    print!("{output}");
    std::io::stdout()
        .flush()
        .context("failed to flush stdout buffer")?;
    Ok(())
}

/// Generates journal and snark seal as a pair (`Vec<u8>`, `Vec<u8>)
/// for the given elf and input.
/// When `RISC0_DEV_MODE` is set, executes the elf locally.
fn prove(elf: &[u8], input: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let env = ExecutorEnv::builder().write_slice(input).build()?;

    let ctx = VerifierContext::default();
    let receipt = default_prover()
        .prove_with_ctx(env, &ctx, elf, &ProverOpts::groth16())?
        .receipt;

    let journal = receipt.clone().journal.bytes;

    let seal = match is_dev_mode() {
        true => {
            let mut seal = Vec::new();
            seal.extend(vec![0u8; 4]);
            seal.extend(receipt.claim()?.digest().as_bytes());
            seal
        }
        false => encode(receipt.inner.groth16()?.seal.clone())?,
    };
    Ok((journal, seal))
}
