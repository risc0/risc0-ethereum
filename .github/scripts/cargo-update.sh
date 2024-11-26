#!/bin/bash
set -e

update(){
  while read path; do
    printf "Project: %s\n" "$path"
    cargo update --manifest-path "$path"
  done
}

grep -rl --include "Cargo.toml" '\[workspace\]' | sort -u | update
