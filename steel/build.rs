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

use anyhow::{Context, Result};
use globset::Glob;
use regex::Regex;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const SOURCE: &str = "src/vendor/git/ethereum-consensus/ethereum-consensus/src";
const TARGET: &str = "src/vendor/ethereum_consensus";

fn main() -> Result<()> {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?);
    let source_dir = manifest_dir.join(SOURCE);
    let vendor_dir = manifest_dir.join(TARGET);

    // copy vendored crate and prepare it
    if vendor_dir.exists() {
        fs::remove_dir_all(&vendor_dir)
            .with_context(|| format!("failed to remove directory: {}", vendor_dir.display()))?;
    }
    copy_dir::copy_dir(&source_dir, &vendor_dir).with_context(|| {
        format!(
            "failed to copy directory from {} to {}",
            source_dir.display(),
            vendor_dir.display()
        )
    })?;
    fs::rename(vendor_dir.join("lib.rs"), vendor_dir.join("mod.rs")).with_context(|| {
        format!(
            "failed to rename lib.rs to mod.rs in {}",
            vendor_dir.display()
        )
    })?;

    let replacements = [
        // modify crate paths to point to the new vendored location
        (
            Regex::new(r"crate\s*::")?,
            "crate::vendor::ethereum_consensus::",
        ),
        // disable all features, which are not "serde"
        (
            Regex::new(r#"feature\s*=\s*"(?:[^s]|s[^e]|se[^r]|ser[^d]|serd[^e]|serde.).*""#)?,
            "any()",
        ),
        // always enable the "serde" feature
        // replacing with `all()`, instead would be preferable, however this is blocked by:
        // https://github.com/rust-lang/rust-clippy/issues/13007
        (
            Regex::new(r#"feature\s*=\s*"serde""#)?,
            r#"feature = "ethereum-consensus""#,
        ),
    ];
    // apply replacements to all .rs files in vendored crate
    modify_files(&vendor_dir, Glob::new("*.rs")?, &replacements)?;

    // remove the networking module from mod.rs
    let replacements = [(
        Regex::new(r"(pub(?:\(crate\))?\s*)?mod\s+networking\s*;")?,
        "",
    )];
    modify_files(&vendor_dir, Glob::new("mod.rs")?, &replacements)?;

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", SOURCE);

    Ok(())
}

fn modify_files(root: impl AsRef<Path>, glob: Glob, replacements: &[(Regex, &str)]) -> Result<()> {
    let glob = glob.compile_matcher();

    // iterate over all files in the root
    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let relative_path = path.strip_prefix(&root).expect("should be a child");
        if glob.is_match(relative_path) {
            // modify the file
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read file: {}", path.display()))?;
            let content = replacements.iter().fold(content, |acc, (re, rep)| {
                re.replace_all(&acc, *rep).to_string()
            });
            fs::write(path, content)
                .with_context(|| format!("failed to write file: {}", path.display()))?;
        }
    }

    Ok(())
}
