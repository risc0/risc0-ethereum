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

use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));

    let mut foundry_root = manifest_dir.clone();
    foundry_root.pop();
    foundry_root.push("contracts");
    println!("foundry root: {}", foundry_root.display());

    // Make sure the Verifier.sol file is always compiled.
    let status = Command::new("forge")
        .arg("build")
        .arg("src/Verifier.sol")
        .arg("--root")
        .arg(foundry_root)
        .status()
        .expect("failed to execute process");
    assert!(status.success(), "forge build failed");

    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=../contracts/Verifier.sol");
}
