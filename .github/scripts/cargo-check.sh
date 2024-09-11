#!/bin/bash
set -e

fmt_sort(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo fmt --all --check --manifest-path "$path"
    (cd "${path%/*}"; cargo sort --workspace --check)
  done
}

grep -rl --include "Cargo.toml" '\[workspace\]' | sort -u | fmt_sort
