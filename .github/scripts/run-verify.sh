#!/bin/bash
set -e

run_verify(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo run -F verify --manifest-path "$path"
  done
}

grep -rlz --include "Cargo.toml" 'verify\s*=\s*\[[^\[]*\]' | sort -u | run_verify
