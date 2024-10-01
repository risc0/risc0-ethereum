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

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_anvil_with_wallet_and_config(|anvil| anvil.fork(rpc_url));

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
