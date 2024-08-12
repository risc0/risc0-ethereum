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

use std::time::Duration;

use alloy::{
    network::Ethereum, providers::Provider, rpc::types::TransactionReceipt, sol,
    transports::Transport,
};
use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::SolEvent;
use anyhow::{bail, ensure, Context, Result};
use tokio::time;

use crate::{
    contracts::{
        IBookmark::IBookmarkInstance, IL1CrossDomainMessenger::IL1CrossDomainMessengerInstance,
        IL2CrossDomainMessenger::IL2CrossDomainMessengerInstance,
    },
    Message,
};

sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/IL1CrossDomainMessenger.sol"
);

sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/IL2CrossDomainMessenger.sol"
);

// Contract to bookmark L1 blocks for later verification.
sol!(
    #[sol(rpc, all_derives)]
    "../contracts/src/IBookmark.sol"
);

#[derive(Clone)]
pub struct IL1CrossDomainMessengerService<T, P> {
    instance: IL1CrossDomainMessengerInstance<T, P, Ethereum>,
}

impl<T, P> IL1CrossDomainMessengerService<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + 'static,
{
    pub const TX_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new(address: Address, provider: P) -> Self {
        let instance = IL1CrossDomainMessenger::new(address, provider);

        IL1CrossDomainMessengerService { instance }
    }

    pub fn instance(&self) -> &IL1CrossDomainMessengerInstance<T, P, Ethereum> {
        &self.instance
    }

    pub async fn contains(&self, digest: B256) -> Result<bool> {
        tracing::debug!("Calling contains({:?})", digest);
        let call = self.instance.contains(digest);
        let result = call.call().await?;
        Ok(result._0)
    }

    pub async fn send_message(&self, target: Address, data: Bytes) -> Result<(Message, u64)> {
        tracing::debug!("Calling sendMessage({:?},{:?})", target, data);
        let call = self.instance.sendMessage(target, data);
        let pending_tx = call.send().await?;
        tracing::debug!("Broadcasting tx {}", pending_tx.tx_hash());
        let receipt = pending_tx
            .with_timeout(Some(Self::TX_TIMEOUT))
            .get_receipt()
            .await?;

        // Process the transaction result
        ensure!(receipt.status(), "transaction failed");
        let message_block_number = receipt.block_number.unwrap();
        let event: IL1CrossDomainMessenger::SentMessage = into_event(receipt)?;
        println!("Message submitted on L1: {:?}", event);
        let message = Message {
            target: event.target,
            sender: event.sender,
            data: event.data,
            nonce: event.messageNonce,
        };

        Ok((message, message_block_number))
    }
}

#[derive(Clone)]
pub struct IL2CrossDomainMessengerService<T, P> {
    instance: IL2CrossDomainMessengerInstance<T, P, Ethereum>,
}

impl<T, P> IL2CrossDomainMessengerService<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + 'static,
{
    pub const TX_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new(address: Address, provider: P) -> Self {
        let instance = IL2CrossDomainMessenger::new(address, provider);

        IL2CrossDomainMessengerService { instance }
    }

    pub fn instance(&self) -> &IL2CrossDomainMessengerInstance<T, P, Ethereum> {
        &self.instance
    }

    pub async fn relay_message(&self, journal: Bytes, seal: Bytes) -> Result<B256> {
        tracing::debug!("Calling relayMessage({:?},{:?})", journal, seal);
        let call = self.instance.relayMessage(journal, seal);
        let pending_tx = call.send().await?;
        tracing::debug!("Broadcasting tx {}", pending_tx.tx_hash());
        let receipt = pending_tx
            .with_timeout(Some(Self::TX_TIMEOUT))
            .get_receipt()
            .await?;

        let event = into_event::<IL2CrossDomainMessenger::RelayedMessage>(receipt)?;
        Ok(event.msgHash)
    }
}

#[derive(Clone)]
pub struct IBookmarkService<T, P> {
    instance: IBookmarkInstance<T, P, Ethereum>,
}

impl<T, P> IBookmarkService<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + 'static,
{
    pub const TX_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new(address: Address, provider: P) -> Self {
        let instance = IBookmark::new(address, provider);

        IBookmarkService { instance }
    }

    pub fn instance(&self) -> &IBookmarkInstance<T, P, Ethereum> {
        &self.instance
    }

    pub async fn bookmark(&self, message_block_number: u64) -> Result<u64> {
        // Call IBookmark.bookmarkL1Block until we can bookmark a block that contains the sent message.
        let bookmark_call = self.instance.bookmarkL1Block();
        loop {
            let current_block_number = bookmark_call.call().await?._0;
            if current_block_number >= message_block_number {
                break;
            }
            println!(
                "Waiting for L1 block to catch up: {} < {}",
                current_block_number, message_block_number
            );
            time::sleep(Duration::from_secs(5)).await;
        }

        // Send a transaction calling IBookmark.bookmarkL1Block to create an on-chain bookmark.
        let pending_tx = bookmark_call
            .send()
            .await
            .context("failed to send bookmarkL1Block")?;
        let receipt = pending_tx
            .with_timeout(Some(Duration::from_secs(60)))
            .get_receipt()
            .await
            .context("failed to confirm tx")?;

        // Get the number of the actual bookmarked block.
        let event: IBookmark::BookmarkedL1Block = into_event(receipt)?;
        let bookmark_block_number = event.number;

        Ok(bookmark_block_number)
    }
}

fn into_event<E: SolEvent>(receipt: TransactionReceipt) -> Result<E> {
    ensure!(receipt.status(), "transaction failed");
    for log in receipt.inner.logs() {
        match log.log_decode::<E>() {
            Ok(decoded_log) => return Ok(decoded_log.inner.data),
            Err(_) => {}
        }
    }
    bail!("invalid events emitted")
}
