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

//! A simple Beacon API client.

use super::consensus::{mainnet::SignedBeaconBlock, phase0::SignedBeaconBlockHeader};
use alloy_primitives::B256;
use ethereum_consensus::Fork;
use reqwest::IntoUrl;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use std::{collections::HashMap, fmt::Display, result::Result as StdResult};
use url::Url;

/// Errors returned by the [BeaconClient].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("could not parse URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("block does not contain an execution payload")]
    NoExecutionPayload,
    #[error("response is empty")]
    EmptyResponse,
}

/// Alias for Results returned by client methods.
pub type Result<T> = StdResult<T, Error>;

/// Response returned by the `get_block_header` API.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockHeaderResponse {
    pub root: B256,
    pub canonical: bool,
    pub header: SignedBeaconBlockHeader,
}

/// Generic wrapper structure for API responses containing data and metadata.
#[derive(Debug, Serialize, Deserialize)]
struct Response<T> {
    data: T,
    #[serde(flatten)]
    meta: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawVersionedJsonResponse<'a> {
    version: Fork,
    #[serde(borrow)]
    data: &'a serde_json::value::RawValue,
    #[serde(flatten)]
    meta: HashMap<String, serde_json::Value>,
}

impl<'de> serde::Deserialize<'de> for Response<SignedBeaconBlock> {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let RawVersionedJsonResponse {
            version,
            data,
            meta,
        } = RawVersionedJsonResponse::deserialize(deserializer)?;
        let data = match version {
            Fork::Phase0 => serde_json::from_str(data.get()).map(SignedBeaconBlock::Phase0),
            Fork::Altair => serde_json::from_str(data.get()).map(SignedBeaconBlock::Altair),
            Fork::Bellatrix => serde_json::from_str(data.get()).map(SignedBeaconBlock::Bellatrix),
            Fork::Capella => serde_json::from_str(data.get()).map(SignedBeaconBlock::Capella),
            Fork::Deneb => serde_json::from_str(data.get()).map(SignedBeaconBlock::Deneb),
            Fork::Electra => serde_json::from_str(data.get()).map(SignedBeaconBlock::Electra),
        }
        .map_err(serde::de::Error::custom)?;

        Ok(Self { data, meta })
    }
}

/// Simple beacon API client for the `mainnet` preset that can query headers and blocks.
#[derive(Debug, Clone)]
pub struct BeaconClient {
    http: reqwest::Client,
    endpoint: Url,
}

impl BeaconClient {
    /// Creates a new beacon endpoint API client.
    pub fn new<U: IntoUrl>(endpoint: U) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::new(),
            endpoint: endpoint.into_url()?,
        })
    }

    async fn get_json<R: DeserializeOwned, T: Serialize>(
        &self,
        path: &str,
        query: Option<&T>,
    ) -> Result<R> {
        let target = self.endpoint.join(path)?;
        let mut builder = self.http.get(target);
        if let Some(query) = query {
            builder = builder.query(query)
        };
        let resp = builder.send().await?;
        let value = resp.error_for_status()?.json().await?;
        Ok(value)
    }

    /// Retrieves block details for the given block ID.
    ///
    /// Block ID can be 'head', 'genesis', 'finalized', <slot>, or <root>.
    pub async fn get_block(&self, block_id: impl Display) -> Result<SignedBeaconBlock> {
        let path = format!("eth/v2/beacon/blocks/{block_id}");
        let result: Response<SignedBeaconBlock> = self.get_json(&path, None::<&()>).await?;
        Ok(result.data)
    }

    /// Retrieves block header for the block identified by the given parent root.
    pub async fn get_header_for_parent_root(
        &self,
        parent_root: B256,
    ) -> Result<BlockHeaderResponse> {
        let path = "eth/v1/beacon/headers";
        let params = [("parent_root", parent_root)];
        let mut result: Response<Vec<BlockHeaderResponse>> =
            self.get_json(path, Some(&params)).await?;
        result.data.pop().ok_or(Error::EmptyResponse)
    }

    /// Retrieves the execution bock hash for the given block id.
    pub async fn get_execution_payload_block_hash(&self, block_id: impl Display) -> Result<B256> {
        let block = self.get_block(block_id).await?;
        let execution_payload = block.execution_payload().ok_or(Error::NoExecutionPayload)?;

        Ok(B256::from_slice(execution_payload.block_hash()))
    }
}
