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

use risc0_aggregation::{GuestInput, GuestState};
use risc0_zkvm::{guest::env, sha::Digestible};

// Verify that the state is either the initial state, is a verified output of self_image_id.
fn verify_state(state: &GuestState) {
    if state.is_initial() {
        return;
    }
    env::verify(state.self_image_id, &state.encode()).unwrap();
}

fn main() {
    // Read the input and verify the given state.
    let input: GuestInput = env::read();
    verify_state(&input.state);
    let mut state = input.state;

    // Add the given claims to the set committed by the MerkleMountainRange.
    for claim in input.claims {
        env::verify_integrity(&claim).unwrap();
        state.mmr.push(claim.digest()).unwrap();
    }

    // Finalize the state if requested.
    if input.finalize {
        state.mmr.finalize().unwrap();
    }

    // Commit the encoded state.
    env::commit_slice(&state.encode());
}
