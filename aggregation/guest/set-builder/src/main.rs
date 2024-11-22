// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

#![no_main]

use risc0_aggregation::{GuestInput, GuestOutput};
use risc0_zkvm::{guest::env, sha::Digest};

risc0_zkvm::guest::entry!(main);

fn verify_child(self_image_id: Digest, set_root: Digest) {
    let journal = GuestOutput::new(self_image_id, set_root).abi_encode();
    env::verify(self_image_id, &journal).unwrap();
}

fn run(input: GuestInput) -> GuestOutput {
    let output = input.to_output();
    match input {
        GuestInput::Singleton { claim, .. } => {
            env::verify_integrity(&claim).unwrap();
        }
        GuestInput::Join {
            self_image_id,
            left_set_root,
            right_set_root,
        } => {
            verify_child(self_image_id, left_set_root);
            verify_child(self_image_id, right_set_root);
        }
    }

    output
}

pub fn main() {
    let input: GuestInput = env::read();
    let output = run(input);

    // commit to the ABI encoded output
    env::commit_slice(&output.abi_encode());
}
