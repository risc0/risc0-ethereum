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

use anyhow::Context;
use risc0_ethereum_test_utils::{prove_echo, text_ctx};
use risc0_ethereum_test_utils_guests::ECHO_ID;
use risc0_zkvm::sha;
use risc0_zkvm::sha::Sha256;
use risc0_zkvm::ProverOpts;

#[tokio::test]
async fn basic() -> anyhow::Result<()> {
    // TODO(victor): This message needs to be be a multiple of 4 bytes in length because there is
    // some kind of bug in the `env.stdin().read_to_end()` implementation that causes the end to be
    // padded with zeroes. I am also working on figuring out what is going on.
    const MSG: &str = "hello risc0!";

    let ctx = text_ctx().await.context("failed to setup test context")?;
    let receipt = prove_echo(MSG, ProverOpts::groth16()).await?.receipt;
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
