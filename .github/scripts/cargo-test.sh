#!/bin/bash
set -e

build_test(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo build --workspace --all-features --manifest-path "$path"
    cargo test --workspace --all-features --manifest-path "$path"
  done
}

grep -rl --include "Cargo.toml" '\[workspace\]' | sort -u | build_test
