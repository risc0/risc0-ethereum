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

use core::time::Duration;

use crate::{
    event_query::EventQueryConfig,
    receipt::{decode_seal, decode_seal_with_claim},
    IRiscZeroSetVerifier::{self, IRiscZeroSetVerifierErrors, IRiscZeroSetVerifierInstance},
    IRiscZeroVerifier,
};
use alloy::{
    network::Ethereum,
    primitives::{Address, Bytes, B256},
    providers::Provider,
};
use anyhow::{bail, Context, Result};
use risc0_aggregation::{merkle_path_root, GuestState, MerkleMountainRange, SetInclusionReceipt};
use risc0_zkvm::{
    sha::{Digest, Digestible},
    ReceiptClaim,
};

const TXN_CONFIRM_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone)]
pub struct SetVerifierService<P> {
    instance: IRiscZeroSetVerifierInstance<P, Ethereum>,
    caller: Address,
    tx_timeout: Duration,
    event_query_config: EventQueryConfig,
}

impl<P> SetVerifierService<P>
where
    P: Provider<Ethereum> + 'static + Clone,
{
    pub fn new(address: Address, provider: P, caller: Address) -> Self {
        let instance = IRiscZeroSetVerifier::new(address, provider);

        Self {
            instance,
            caller,
            tx_timeout: TXN_CONFIRM_TIMEOUT,
            event_query_config: EventQueryConfig::default(),
        }
    }

    pub fn instance(&self) -> &IRiscZeroSetVerifierInstance<P, Ethereum> {
        &self.instance
    }

    pub fn with_timeout(self, tx_timeout: Duration) -> Self {
        Self { tx_timeout, ..self }
    }

    /// Sets the event query configuration.
    pub fn with_event_query_config(self, config: EventQueryConfig) -> Self {
        Self {
            event_query_config: config,
            ..self
        }
    }

    pub async fn contains_root(&self, root: B256) -> Result<bool> {
        tracing::debug!("Calling containsRoot({:?})", root);
        let call = self.instance.containsRoot(root);

        call.call().await.context("call failed")
    }

    pub async fn submit_merkle_root(&self, root: B256, seal: Bytes) -> Result<()> {
        tracing::debug!("Calling submitMerkleRoot({:?},{:?})", root, seal);
        let call = self.instance.submitMerkleRoot(root, seal).from(self.caller);
        let pending_tx = call
            .send()
            .await
            .map_err(IRiscZeroSetVerifierErrors::decode_error)?;
        tracing::debug!("Broadcasting tx {}", pending_tx.tx_hash());
        let tx_hash = pending_tx
            .with_timeout(Some(self.tx_timeout))
            .watch()
            .await
            .context("failed to confirm tx")?;

        tracing::info!("Submitted Merkle root {}: {}", root, tx_hash);

        Ok(())
    }

    pub async fn verify(&self, seal: Bytes, image_id: B256, journal_digest: B256) -> Result<()> {
        tracing::debug!(
            "Calling verify({:?},{:?},{:?})",
            seal,
            image_id,
            journal_digest
        );
        let verifier = IRiscZeroVerifier::new(
            *self.instance().address(),
            self.instance().provider().clone(),
        );
        verifier
            .verify(seal, image_id, journal_digest)
            .call()
            .await
            .map_err(|_| anyhow::anyhow!("Verification failed"))?;

        Ok(())
    }

    pub async fn image_info(&self) -> Result<(B256, String)> {
        tracing::debug!("Calling imageInfo()");
        let (image_id, image_url) = self
            .instance
            .imageInfo()
            .call()
            .await
            .context("call failed")?
            .into();

        Ok((image_id, image_url))
    }

    /// Returns the seal if of the given verified root.
    pub async fn fetch_verified_root_seal(&self, root: B256) -> Result<Bytes> {
        self.query_verified_root_event(root, None, None).await
    }

    async fn get_latest_block(&self) -> Result<u64> {
        self.instance
            .provider()
            .get_block_number()
            .await
            .context("Failed to get latest block number")
    }

    /// Query the VerifiedRoot event based on the root and block options.
    ///
    /// For each iteration, we query a range of blocks. If the event is not found, we move the
    /// range down and repeat until we find the event. If the event is not found after the
    /// configured max iterations, we return an error. The default range is set to 100 blocks for
    /// each iteration, and the default maximum number of iterations is 1000. This means that the
    /// search will cover a maximum of 100,000 blocks (~14 days at 12s block times). Optionally,
    /// you can specify a lower and upper bound to limit the search range.
    async fn query_verified_root_event(
        &self,
        root: B256,
        lower_bound: Option<u64>,
        upper_bound: Option<u64>,
    ) -> Result<Bytes> {
        let mut upper_block = if let Some(upper_bound) = upper_bound {
            upper_bound
        } else {
            self.get_latest_block().await?
        };
        let start_block = lower_bound.unwrap_or_else(|| {
            upper_block.saturating_sub(
                self.event_query_config.block_range * self.event_query_config.max_iterations,
            )
        });

        // Loop to progressively search through blocks
        for _ in 0..self.event_query_config.max_iterations {
            // If the current end block is less than the starting block, stop searching
            if upper_block < start_block {
                break;
            }

            // Calculate the block range to query: from [lower_block] to [upper_block]
            let lower_block = upper_block.saturating_sub(self.event_query_config.block_range);

            // Set up the event filter for the specified block range
            let mut event_filter = self.instance.VerifiedRoot_filter();
            event_filter.filter = event_filter
                .filter
                .topic1(root)
                .from_block(lower_block)
                .to_block(upper_block);

            // Query the logs for the event
            let logs = event_filter.query().await?;

            // If we find a log, return the seal
            if let Some((verified_root, _)) = logs.first() {
                let seal = verified_root.seal.clone();
                return Ok(seal);
            }
            // Move the upper_block down for the next iteration
            upper_block = lower_block.saturating_sub(1);
        }

        // Return error if no logs are found after all iterations
        bail!("VerifiedRoot event not found for root {:?}", root);
    }

    /// Decodes a seal into a [SetInclusionReceipt] including a [risc0_zkvm::Groth16Receipt] as its
    /// root.
    pub async fn fetch_receipt(
        &self,
        seal: Bytes,
        image_id: impl Into<Digest>,
        journal: impl Into<Vec<u8>>,
    ) -> Result<SetInclusionReceipt<ReceiptClaim>> {
        let journal = journal.into();
        let claim = ReceiptClaim::ok(image_id, journal.clone());
        self.fetch_receipt_with_claim(seal, claim, journal).await
    }

    /// Decodes a seal into a [SetInclusionReceipt] including a [risc0_zkvm::Groth16Receipt] as its
    /// root.
    pub async fn fetch_receipt_with_claim(
        &self,
        seal: Bytes,
        claim: ReceiptClaim,
        journal: impl Into<Vec<u8>>,
    ) -> Result<SetInclusionReceipt<ReceiptClaim>> {
        let receipt = decode_seal_with_claim(seal, claim.clone(), journal)
            .map_err(|e| anyhow::anyhow!("Failed to decode seal: {:?}", e))?;

        let set_inclusion_receipt = receipt
            .set_inclusion_receipt()
            .ok_or_else(|| anyhow::anyhow!("Seal is not a SetInclusionReceipt"))?;

        let root = merkle_path_root(claim.digest(), &set_inclusion_receipt.merkle_path);
        let root_seal = self
            .fetch_verified_root_seal(<[u8; 32]>::from(root).into())
            .await?;

        let set_builder_id = Digest::from_bytes(self.image_info().await?.0 .0);
        let state = GuestState {
            self_image_id: set_builder_id,
            mmr: MerkleMountainRange::new_finalized(root),
        };
        let aggregation_set_journal = state.encode();

        let root_receipt = decode_seal(root_seal, set_builder_id, aggregation_set_journal)?
            .receipt()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Failed to decode root seal"))?;

        let receipt = set_inclusion_receipt.clone().with_root(root_receipt);

        Ok(receipt)
    }
}
