#!/bin/bash
set -e

clippy(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo clippy $CARGO_LOCKED --workspace --all-targets --all-features --manifest-path "$path"
  done
}

grep -rl --include "Cargo.toml" '\[workspace\]' | sort -u | clippy
