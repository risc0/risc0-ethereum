#!/bin/bash
set -e

fmt_sort_clippy(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo fmt --all --check --manifest-path "$path"
    (cd "${path%/*}"; cargo sort --workspace --check)
    RISC0_SKIP_BUILD=true cargo clippy --workspace --all-targets --all-features --manifest-path "$path" -- -D warnings
  done
}

grep -rl --include "Cargo.toml" '\[workspace\]' | sort -u | fmt_sort_clippy
