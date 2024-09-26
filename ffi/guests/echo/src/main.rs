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

use std::io::Read;

use risc0_zkvm::guest::env;

pub fn main() {
    // Read the entire input stream as raw bytes.
    let mut message = Vec::<u8>::new();
    env::stdin().read_to_end(&mut message).unwrap();

    // Commit exactly what the host provided to the journal.
    env::commit_slice(message.as_slice());
}
