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

use std::{
    fs::{File, OpenOptions},
    io,
    io::Write,
    os::unix::io::{AsRawFd, FromRawFd},
};

use alloy::sol_types::SolValue;
use anyhow::{ensure, Context, Result};
use clap::Parser;
use risc0_ethereum_contracts::encode_seal;
use risc0_forge_ffi::JournalSeal;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

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
    // Take stdout is ensure no extra data is written to it.
    let mut stdout = take_stdout()?;

    let output = match Command::parse() {
        Command::Prove {
            guest_binary_path,
            input,
        } => prove_ffi(
            guest_binary_path,
            hex::decode(input.strip_prefix("0x").unwrap_or(&input))?,
        )?,
    };

    // Forge test FFI calls expect hex encoded bytes sent to stdout
    write!(&mut stdout, "{}", hex::encode(output)).context("failed to write to stdout")?;
    stdout.flush().context("failed to flush stdout")?;

    Ok(())
}

/// Prints on stdio the Ethereum ABI and hex encoded proof.
fn prove_ffi(elf_path: String, input: Vec<u8>) -> Result<Vec<u8>> {
    let elf = std::fs::read(elf_path).expect("failed to read guest ELF");
    let (journal, seal) = prove(&elf, &input)?;
    let calldata = JournalSeal {
        journal: journal.into(),
        seal: seal.into(),
    };
    Ok(calldata.abi_encode())
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
    let seal = encode_seal(&receipt)?;
    Ok((journal, seal))
}

/// "Takes" stdout, returning a handle and ensuring no other code in this process can write to it.
/// This is used to ensure that no additional data (e.g. log lines) is written to stdout, as any
/// extra will cause a decoding failure in the Forge FFI cheatcode.
fn take_stdout() -> Result<File> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    // Ensure all buffered data is written before redirection
    handle.flush()?;

    let devnull = OpenOptions::new().write(true).open("/dev/null")?;

    unsafe {
        // Create a copy of stdout to use for our output.
        let dup_fd = libc::dup(handle.as_raw_fd());
        ensure!(dup_fd >= 0, "call to libc::dup failed: {}", dup_fd);
        // Redirect stdout to the fd we opened for /dev/null
        let dup2_result = libc::dup2(devnull.as_raw_fd(), libc::STDOUT_FILENO);
        ensure!(
            dup2_result >= 0,
            "call to libc::dup2 failed: {}",
            dup2_result
        );
        Ok(File::from_raw_fd(dup_fd))
    }
}
