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

//! Utilities for tests within the `steel` crate that require external RPC node access.

use std::env;
use url::Url;

const ETH_RPC_URL_KEY: &str = "ETH_RPC_URL";
const BEACON_API_URL_KEY: &str = "BEACON_API_URL";
const DEFAULT_EL_URL: &str = "https://ethereum-rpc.publicnode.com";
const DEFAULT_CL_URL: &str = "https://ethereum-beacon-api.publicnode.com";

/// Retrieves the Ethereum Execution Layer (EL) RPC URL for tests.
///
/// This function is intended for use within tests gated by the `rpc-tests` feature.
pub fn get_el_url() -> Url {
    get_url(ETH_RPC_URL_KEY, DEFAULT_EL_URL)
}

/// Retrieves the Ethereum Consensus Layer (CL) Beacon API URL for tests.
///
/// This function is intended for use within tests gated by the `rpc-tests` feature.
pub fn get_cl_url() -> Url {
    get_url(BEACON_API_URL_KEY, DEFAULT_CL_URL)
}

fn get_url(key: &str, default: &str) -> Url {
    match env::var(key) {
        Ok(rpc_url_str) => rpc_url_str.parse().unwrap_or_else(|err| {
            panic!("Environment variable {} is not a valid URL: {}", key, err)
        }),
        Err(env::VarError::NotPresent) => {
            let url = default.parse().expect("Default URL is not valid");
            eprintln!(
                "Warning: Environment variable {} not set. Using default URL '{}'",
                key, default
            );
            url
        }
        Err(env::VarError::NotUnicode(_)) => {
            panic!("Environment variable {} contains invalid unicode", key)
        }
    }
}
