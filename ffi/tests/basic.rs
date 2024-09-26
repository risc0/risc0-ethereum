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

use std::process::Command;

use alloy::{primitives::Bytes, sol_types::SolValue};
use ffi_guests::{ECHO_ID, ECHO_PATH};
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::{FakeReceipt, InnerReceipt, Receipt, ReceiptClaim};

#[test]
fn main() {
    let exe_path = env!("CARGO_BIN_EXE_risc0-forge-ffi");
    let args = ["prove", ECHO_PATH, "0xdeadbeef"];
    println!("{} {:?}", exe_path, args);
    let output = Command::new(exe_path)
        .env_clear()
        // PATH is required so r0vm can be found.
        .env("PATH", std::env::var("PATH").unwrap())
        .env("RISC0_DEV_MODE", "1")
        .args(args)
        .output()
        .unwrap();

    println!("{:#?}", &output);

    let output_bytes = hex::decode(output.stdout).unwrap();
    let (journal, seal) = <(Bytes, Bytes)>::abi_decode(&output_bytes, true).unwrap();

    assert_eq!(journal, hex::decode("deadbeef").unwrap());
    let expected_receipt = Receipt::new(
        InnerReceipt::Fake(FakeReceipt::new(ReceiptClaim::ok(
            ECHO_ID,
            journal.to_vec(),
        ))),
        journal.into(),
    );
    let expect_seal = encode_seal(&expected_receipt).unwrap();
    assert_eq!(expect_seal, seal.to_vec());
}
