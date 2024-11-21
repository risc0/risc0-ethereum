use std::process::Command;

fn main() {
    // assure that the Verifier.sol file is always compiled
    let status = Command::new("forge")
        .arg("build")
        .arg("Verifier.sol")
        .current_dir("../contracts")
        .status()
        .expect("failed to execute process");
    assert!(status.success());

    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=../contracts/Verifier.sol");
}
