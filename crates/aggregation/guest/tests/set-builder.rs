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

use guest_set_builder::{SET_BUILDER_ELF, SET_BUILDER_ID};
use rand::{rng, Rng};
use risc0_aggregation::{merkle_root, GuestState};
use risc0_zkvm::{
    default_executor, sha::Digestible, ExecutorEnv, FakeReceipt, InnerReceipt, MaybePruned,
    ReceiptClaim,
};

fn random_claim() -> ReceiptClaim {
    ReceiptClaim::ok(
        rand::random::<[u8; 32]>(),
        MaybePruned::Pruned(rand::random::<[u8; 32]>().into()),
    )
}

#[test]
fn proves_nop() {
    let env = ExecutorEnv::builder()
        .write(
            &GuestState::initial(SET_BUILDER_ID)
                .into_input(vec![], false)
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();

    // NOTE: Use the executor to run tests without proving.
    let session_info = default_executor().execute(env, SET_BUILDER_ELF).unwrap();
    let state = GuestState::decode(&session_info.journal.bytes).unwrap();

    assert_eq!(state.self_image_id, SET_BUILDER_ID.into());
    assert!(state.mmr.is_empty());
}

#[test]
fn proves_one_step() {
    for length in 1..32 {
        let claims: Vec<ReceiptClaim> = (0..length).map(|_| random_claim()).collect();

        let mut env_builder = ExecutorEnv::builder();
        env_builder
            .write(
                &GuestState::initial(SET_BUILDER_ID)
                    .into_input(claims.clone(), true)
                    .unwrap(),
            )
            .unwrap();
        for claim in claims.iter() {
            let receipt = InnerReceipt::Fake(FakeReceipt::new(claim.clone()));
            env_builder.add_assumption(receipt);
        }
        let env = env_builder.build().unwrap();

        // NOTE: Use the executor to run tests without proving.
        let session_info = default_executor().execute(env, SET_BUILDER_ELF).unwrap();
        let state = GuestState::decode(&session_info.journal.bytes).unwrap();

        assert!(state.mmr.is_finalized());
        assert_eq!(
            state.mmr.finalized_root().unwrap(),
            merkle_root(
                &claims
                    .iter()
                    .map(|claim| claim.digest())
                    .collect::<Vec<_>>()
            )
        );
    }
}

#[test]
fn proves_two_step() {
    for length in 1..32 {
        let claims: Vec<ReceiptClaim> = (0..length).map(|_| random_claim()).collect();

        let mut env_builder = ExecutorEnv::builder();
        env_builder
            .write(
                &GuestState::initial(SET_BUILDER_ID)
                    .into_input(claims.clone(), false)
                    .unwrap(),
            )
            .unwrap();
        for claim in claims.iter() {
            let receipt = InnerReceipt::Fake(FakeReceipt::new(claim.clone()));
            env_builder.add_assumption(receipt);
        }
        let env = env_builder.build().unwrap();

        // NOTE: Use the executor to run tests without proving.
        let session_info = default_executor().execute(env, SET_BUILDER_ELF).unwrap();
        let state = GuestState::decode(&session_info.journal.bytes).unwrap();

        assert!(!state.mmr.is_finalized());

        let mut env_builder = ExecutorEnv::builder();
        env_builder
            .write(&state.into_input(vec![], true).unwrap())
            .unwrap()
            .add_assumption(session_info.receipt_claim.unwrap());
        for claim in claims.iter() {
            let receipt = InnerReceipt::Fake(FakeReceipt::new(claim.clone()));
            env_builder.add_assumption(receipt);
        }
        let env = env_builder.build().unwrap();

        // NOTE: Use the executor to run tests without proving.
        let session_info = default_executor().execute(env, SET_BUILDER_ELF).unwrap();
        let state = GuestState::decode(&session_info.journal.bytes).unwrap();

        assert!(state.mmr.is_finalized());
        assert_eq!(
            state.mmr.finalized_root().unwrap(),
            merkle_root(
                &claims
                    .iter()
                    .map(|claim| claim.digest())
                    .collect::<Vec<_>>()
            )
        );
    }
}

#[test]
fn proves_incremental() {
    for length in 1..16 {
        // Incrementally feed in the claims to build the Merkle tree.
        let mut claims: Vec<ReceiptClaim> = (0..length).map(|_| random_claim()).collect();
        let mut claims_incremental = vec![];
        let mut state = GuestState::initial(SET_BUILDER_ID);
        let mut set_builder_claim: Option<ReceiptClaim> = None;
        while !claims.is_empty() {
            let chunk = claims.split_off(rng().random_range(0..claims.len()));

            let mut env_builder = ExecutorEnv::builder();
            env_builder
                .write(&state.clone().into_input(chunk.clone(), false).unwrap())
                .unwrap();
            for claim in chunk.iter() {
                let receipt = InnerReceipt::Fake(FakeReceipt::new(claim.clone()));
                env_builder.add_assumption(receipt);
            }
            if let Some(set_builder_claim) = set_builder_claim {
                let receipt = InnerReceipt::Fake(FakeReceipt::new(set_builder_claim));
                env_builder.add_assumption(receipt);
            }
            let env = env_builder.build().unwrap();

            // NOTE: Use the executor to run tests without proving.
            let session_info = default_executor().execute(env, SET_BUILDER_ELF).unwrap();
            state = GuestState::decode(&session_info.journal.bytes).unwrap();
            set_builder_claim = Some(session_info.receipt_claim.unwrap());
            claims_incremental.extend_from_slice(&chunk);

            assert!(!state.mmr.is_finalized());
            assert_eq!(
                state.clone().mmr.finalized_root().unwrap(),
                merkle_root(
                    &claims_incremental
                        .iter()
                        .map(|claim| claim.digest())
                        .collect::<Vec<_>>()
                )
            );
        }

        // One more run to finalize the state.
        let env = ExecutorEnv::builder()
            .write(&state.clone().into_input(vec![], true).unwrap())
            .unwrap()
            .add_assumption(InnerReceipt::Fake(FakeReceipt::new(
                set_builder_claim.unwrap(),
            )))
            .build()
            .unwrap();

        // NOTE: Use the executor to run tests without proving.
        let session_info = default_executor().execute(env, SET_BUILDER_ELF).unwrap();
        state = GuestState::decode(&session_info.journal.bytes).unwrap();

        assert!(state.mmr.is_finalized());
        assert_eq!(
            state.mmr.finalized_root().unwrap(),
            merkle_root(
                &claims_incremental
                    .iter()
                    .map(|claim| claim.digest())
                    .collect::<Vec<_>>()
            )
        );
    }
}

#[test]
fn rejects_no_claim_receipt_provided() {
    // NOTE: We dont provide an assumption receipt here.
    let env = ExecutorEnv::builder()
        .write(
            &GuestState::initial(SET_BUILDER_ID)
                .into_input(vec![random_claim()], true)
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();

    let err = default_executor()
        .execute(env, SET_BUILDER_ELF)
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("no receipt found to resolve assumption"));
}

#[test]
fn rejects_no_set_builder_receipt_provided() {
    let claim = random_claim();
    let env = ExecutorEnv::builder()
        .write(
            &GuestState::initial(SET_BUILDER_ID)
                .into_input(vec![claim.clone()], false)
                .unwrap(),
        )
        .unwrap()
        .add_assumption(InnerReceipt::Fake(FakeReceipt::new(claim)))
        .build()
        .unwrap();

    let session_info = default_executor().execute(env, SET_BUILDER_ELF).unwrap();
    let state = GuestState::decode(&session_info.journal.bytes).unwrap();

    // NOTE: We dont provide a set builder receipt here.
    let env = ExecutorEnv::builder()
        .write(&state.into_input(vec![], true).unwrap())
        .unwrap()
        .build()
        .unwrap();

    let err = default_executor()
        .execute(env, SET_BUILDER_ELF)
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("no receipt found to resolve assumption"));
}
