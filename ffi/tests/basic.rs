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
