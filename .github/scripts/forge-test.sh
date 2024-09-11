#!/bin/bash
set -e

test(){
  while read path; do
    printf "Project: %s\n" "$path"
    (cd "${path%/*}"; forge test -vvvv)
  done
}

find . -maxdepth 2 -mindepth 2 -name 'foundry.toml' | sort -u | test
