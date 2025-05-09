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

#![allow(unused_doc_comments)]
#![no_main]

use l2_to_l1_core::{CALL, CALLER, CONTRACT};
use risc0_op_steel::{
    optimism::{OpEvmInput, OP_MAINNET_CHAIN_SPEC},
    Contract,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read the input from the guest environment.
    let input: OpEvmInput = env::read();

    // Create the environment and add the commitment.
    let env = input.into_env(&OP_MAINNET_CHAIN_SPEC);
    env::commit_slice(&env.commitment().abi_encode());

    // Execute the call.
    let contract = Contract::new(CONTRACT, &env);
    let mut builder = contract.call_builder(&CALL);
    builder.tx.base.caller = CALLER;
    let returns = builder.call();

    // Commit the result.
    env::commit(&returns)
}
