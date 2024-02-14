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

use std::{sync::Arc, time::SystemTime};

use bonsai_sdk::{
    alpha::Client as BonsaiClient,
    alpha_async::{get_client_from_parts, session_status, upload_img},
};
use ethers::prelude::*;
use ethers::types::{Bytes, H256 as ethers_H256, U256};
use risc0_ethereum_contracts::{
    testutils::Counter, BonsaiRelay, BonsaiTestRelay, RiscZeroGroth16Verifier,
};
use risc0_ethereum_relay::{
    sdk::{
        client::{CallbackRequest, Client},
        utils,
    },
    Relayer,
};
use risc0_ethereum_relay_test_methods::{SLICE_IO_ELF, SLICE_IO_ID};
use serial_test::serial;
use tokio::time::{sleep, Duration};

const BONSAI_API_URI: &str = "http://localhost:8081";

fn get_bonsai_url() -> String {
    let endpoint = match std::env::var("BONSAI_API_URL") {
        Ok(endpoint) => endpoint,
        Err(_) => BONSAI_API_URI.to_string(),
    };

    endpoint
        .is_empty()
        .then(|| BONSAI_API_URI.to_string())
        .unwrap_or(endpoint)
}

fn get_api_key() -> String {
    match std::env::var("BONSAI_API_KEY") {
        Ok(api_key) => api_key,
        _ => "test_key".to_string(),
    }
}

async fn get_bonsai_client(api_key: String) -> BonsaiClient {
    let bonsai_api_endpoint = get_bonsai_url();
    get_client_from_parts(bonsai_api_endpoint, api_key, risc0_zkvm::VERSION)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore]
#[serial] // TODO: allow tests to bind to port 0
async fn e2e_test_counter() {
    // Get Anvil
    let anvil = utils::get_anvil();

    // Get client config
    let ethers_client_config = utils::get_ethers_client_config(anvil.as_ref())
        .await
        .expect("Failed to get ethers client config");
    let ethers_client = Arc::new(
        ethers_client_config
            .get_client()
            .await
            .expect("Failed to get ethers client"),
    );

    // Deploy the relay contract, using either the test or fully verifying relay.
    let relay_contract = match risc0_zkvm::is_dev_mode() {
        true => BonsaiTestRelay::deploy(ethers_client.clone(), ethers_client.signer().chain_id())
            .expect("should be able to deploy the BonsaiTestRelay contract")
            .send()
            .await
            .expect("deployment should succeed")
            .address(),
        false => {
            let verifier = RiscZeroGroth16Verifier::deploy(ethers_client.clone(), ())
                .expect("should be able to deploy the BonsaiRelay contract")
                .send()
                .await
                .expect("deployment should succeed")
                .address();

            BonsaiRelay::deploy(ethers_client.clone(), verifier)
                .expect("should be able to deploy the BonsaiRelay contract")
                .send()
                .await
                .expect("deployment should succeed")
                .address()
        }
    };

    let counter = Counter::deploy(ethers_client.clone(), ())
        .expect("should be able to deploy the Counter contract")
        .send()
        .await
        .expect("deployment should succeed");
    assert_eq!(
        counter
            .method::<_, U256>("value", ())
            .expect("value should be a function")
            .call()
            .await
            .expect("a call to value should succeed"),
        U256::from(0),
    );

    // run the bonsai relayer
    let relayer = Relayer {
        rest_api: false,
        dev_mode: risc0_zkvm::is_dev_mode(),
        rest_api_port: "8080".to_string(),
        bonsai_api_url: get_bonsai_url(),
        bonsai_api_key: get_api_key(),
        relay_contract_address: relay_contract,
    };

    dbg!("starting relayer");
    tokio::spawn(relayer.run(ethers_client_config.clone()));

    // wait for relay to start
    sleep(Duration::from_secs(2)).await;

    // register elf
    let bonsai_client = get_bonsai_client(get_api_key()).await;
    // create the memoryImg, upload it and return the imageId
    let image_id_bytes: [u8; 32] = bytemuck::cast(SLICE_IO_ID);
    let image_id = hex::encode(image_id_bytes);
    upload_img(
        bonsai_client.clone(),
        image_id.clone(),
        SLICE_IO_ELF.to_vec(),
    )
    .await
    .expect("unable to upload result");

    // Since we are using the True Elf, the first 4 bytes need to be the length
    // of the slice (in little endian)
    let mut input = vec![0; 36];
    input[0] = 32;
    input[35] = 100;

    // Invoke the Counter contract which should request a callback through bonsai
    let gas_limit: u64 = 3000000;
    counter
        .method::<_, ()>(
            "request_callback",
            (
                ethers_H256::from(image_id_bytes),
                Bytes::from(input),
                gas_limit,
                relay_contract,
            ),
        )
        .expect("request_callback should be a function")
        .send()
        .await
        .expect("request_callback should succeed");

    let now = SystemTime::now();
    let max_seconds_to_wait = 120;
    let expected_value = U256::from(100);
    let mut value = U256::from(0);
    while now.elapsed().expect("error occured getting time").as_secs() < max_seconds_to_wait {
        value = counter
            .method::<_, U256>("value", ())
            .expect("value should be a function")
            .call()
            .await
            .expect("a call to value should succeed");

        if value == expected_value {
            // noticed in dev e2e tests, this condition returns true but the
            // assertion at the end of the test fails. I believe this is because
            // Infura does not ask the same node that returned the value for this
            // call. Adding a sleep of 5 seconds to allow for nodes to sync and
            // catch up.
            dbg!("Success! Waiting 5 seconds for nodes to catch up...");
            sleep(Duration::new(5, 0)).await;
            break;
        }

        dbg!(
            format!("waiting {max_seconds_to_wait} seconds for bridge to finish"),
            now.elapsed().expect("valid time").as_secs(),
        );
        sleep(Duration::new(1, 0)).await
    }
    assert_eq!(value, expected_value)
}

#[tokio::test]
#[ignore]
#[serial] // TODO: allow tests to bind to port 0
async fn e2e_test_counter_publish_mode() {
    // Get Anvil
    let anvil = utils::get_anvil();
    // Get client config
    let ethers_client_config = utils::get_ethers_client_config(anvil.as_ref())
        .await
        .expect("Failed to get ethers client config");
    let ethers_client = Arc::new(
        ethers_client_config
            .get_client()
            .await
            .expect("Failed to get ethers client"),
    );
    let relay_contract = match risc0_zkvm::is_dev_mode() {
        true => BonsaiTestRelay::deploy(ethers_client.clone(), ethers_client.signer().chain_id())
            .expect("should be able to deploy the BonsaiTestRelay contract")
            .send()
            .await
            .expect("deployment should succeed")
            .address(),
        false => {
            let verifier = RiscZeroGroth16Verifier::deploy(ethers_client.clone(), ())
                .expect("should be able to deploy the BonsaiRelay contract")
                .send()
                .await
                .expect("deployment should succeed")
                .address();

            BonsaiRelay::deploy(ethers_client.clone(), verifier)
                .expect("should be able to deploy the BonsaiRelay contract")
                .send()
                .await
                .expect("deployment should succeed")
                .address()
        }
    };
    let counter = Counter::deploy(ethers_client.clone(), ())
        .expect("should be able to deploy the Counter contract")
        .send()
        .await
        .expect("deployment should succeed");
    assert_eq!(
        counter
            .method::<_, U256>("value", ())
            .expect("value should be a function")
            .call()
            .await
            .expect("a call to value should succeed"),
        U256::from(0),
    );

    // run the bonsai relayer
    let relayer = Relayer {
        rest_api: true,
        dev_mode: risc0_zkvm::is_dev_mode(),
        rest_api_port: "8080".to_string(),
        bonsai_api_url: get_bonsai_url(),
        bonsai_api_key: get_api_key(),
        relay_contract_address: relay_contract,
    };

    dbg!("starting relayer");
    tokio::spawn(relayer.run(ethers_client_config.clone()));

    // wait for relay to start
    sleep(Duration::from_secs(2)).await;

    // register elf
    let bonsai_client = get_bonsai_client(get_api_key()).await;
    // create the memoryImg, upload it and return the imageId
    let image_id_bytes: [u8; 32] = bytemuck::cast(SLICE_IO_ID);
    let image_id = hex::encode(image_id_bytes);
    upload_img(
        bonsai_client.clone(),
        image_id.clone(),
        SLICE_IO_ELF.to_vec(),
    )
    .await
    .expect("unable to upload result");

    // Since we are using the True Elf, the first 4 bytes need to be the length
    // of the slice (in little endian)
    let mut input = vec![0; 36];
    input[0] = 32;
    input[35] = 100;

    // Invoke the Counter contract which should request a callback through bonsai
    let gas_limit: u64 = 3000000;
    let request = CallbackRequest {
        callback_contract: counter.address(),
        function_selector: [0xff, 0x58, 0x5c, 0xaf],
        gas_limit,
        image_id: image_id_bytes,
        input,
    };

    let relay_client =
        Client::from_parts("http://localhost:8080".to_string(), get_api_key()).unwrap();

    let session_id = relay_client
        .callback_request(request)
        .await
        .expect("Callback request failed");

    let session_status = session_status(bonsai_client.clone(), session_id)
        .await
        .expect("session status failed");
    dbg!(session_status.status);

    let now = SystemTime::now();
    let max_seconds_to_wait = 120;
    let expected_value = U256::from(100);
    let mut value = U256::from(0);
    while now.elapsed().expect("error occured getting time").as_secs() < max_seconds_to_wait {
        value = counter
            .method::<_, U256>("value", ())
            .expect("value should be a function")
            .call()
            .await
            .expect("a call to value should succeed");

        if value == expected_value {
            break;
        }

        dbg!(
            format!("waiting {max_seconds_to_wait} seconds for bridge to finish"),
            now.elapsed().expect("valid time").as_secs(),
        );
        sleep(Duration::new(1, 0)).await
    }
    assert_eq!(value, expected_value)
}
