#!/bin/bash
set -e

build_test(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo build --workspace --all-features --manifest-path "$path"
    cargo test --workspace --all-features --manifest-path "$path"
  done
}

find . -maxdepth 2 -mindepth 2 -name 'Cargo.toml' | sort -u | build_test
