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

find . -maxdepth 2 -mindepth 2 -name 'Cargo.toml' | sort -u | fmt_sort_clippy
