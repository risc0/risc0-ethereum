#!/bin/bash
set -e

clippy(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo clippy --workspace --all-targets --all-features --manifest-path "$path"
  done
}

grep -rl --include "Cargo.toml" '\[workspace\]' | sort -u | clippy
