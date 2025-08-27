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

use alloy::node_bindings::Anvil;
use anyhow::Context;
use risc0_ethereum_test_utils::{prove_echo, test_ctx_with};
use risc0_ethereum_test_utils_guests::ECHO_ID;
use risc0_zkvm::sha::Sha256;
use risc0_zkvm::ProverOpts;
use risc0_zkvm::{sha, VerifierContext};
use tokio::sync::Mutex;

#[tokio::test]
async fn basic() -> anyhow::Result<()> {
    const MSG: &str = "hello risc0!";

    let anvil = Anvil::new().spawn();
    // On MacOS, we cannot produce a Groth16 proof (risc0#1749), so we always set dev mode.
    let verifier_ctx = if cfg!(target_os = "macos") {
        VerifierContext::default().with_dev_mode(true)
    } else {
        VerifierContext::default()
    };
    let prover_opts = ProverOpts::groth16().with_dev_mode(verifier_ctx.dev_mode());

    let ctx = test_ctx_with(Mutex::new(anvil).into(), 0, verifier_ctx).await?;
    let receipt = prove_echo(MSG, prover_opts).await?.receipt;
    let encoded_seal = risc0_ethereum_contracts::encode_seal(&receipt)?;
    let journal_digest = sha::Impl::hash_bytes(MSG.as_ref());
    ctx.verifier
        .verify(
            encoded_seal.into(),
            bytemuck::cast::<_, [u8; 32]>(ECHO_ID).into(),
            bytemuck::cast::<_, [u8; 32]>(*journal_digest).into(),
        )
        .call()
        .await
        .context("verifier call failed")?;
    Ok(())
}
