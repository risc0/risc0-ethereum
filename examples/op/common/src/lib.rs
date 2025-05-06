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

use alloy::providers::ProviderBuilder;
use anyhow::Context;
use risc0_zkvm::{sha::Digest, Receipt};
use url::Url;

pub async fn verify_on_chain(
    receipt: Receipt,
    image_id: Digest,
    rpc_url: Url,
) -> anyhow::Result<()> {
    log::info!("Validating the receipt on {}...", rpc_url);

    let seal = risc0_ethereum_contracts::encode_seal(&receipt).context("encode_seal failed")?;
    let journal = receipt.journal.bytes;

    let provider =
        ProviderBuilder::new().connect_anvil_with_wallet_and_config(|anvil| anvil.fork(rpc_url))?;

    alloy::sol!(
        #[sol(rpc)]
        Verifier,
        "../contracts/out/Verifier.sol/Verifier.json"
    );

    let verifier = Verifier::deploy(provider)
        .await
        .context("failed to deploy Verifier")?;
    let verify = verifier.verify(
        journal.into(),
        seal.into(),
        <[u8; 32]>::from(image_id).into(),
    );
    log::debug!("Calling {} {}", verifier.address(), verify.calldata());
    verify.call().await?;
    log::info!("Receipt validated");

    Ok(())
}
