#!/bin/bash
set -e

fmt(){
  while read path; do
    printf "Project: %s\n" "$path"
    (cd "${path%/*}"; forge fmt --check)
  done
}

find . -maxdepth 2 -mindepth 2 -name 'foundry.toml' | sort -u | fmt
