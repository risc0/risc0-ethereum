// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(missing_docs)]

use alloy_primitives::{bytes, keccak256, Bytes, B256};
use alloy_trie::{HashBuilder, Nibbles};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use risc0_ethereum_trie::{CachedTrie, Trie};
use std::collections::BTreeMap;

const SIZE: usize = 1024;

pub fn trie(c: &mut Criterion) {
    let mut g = c.benchmark_group("trie");

    g.bench_with_input(BenchmarkId::new("hash_slow", SIZE), &SIZE, |b, &s| {
        let trie = create_trie(&create_leaves(s));
        b.iter(|| {
            _ = black_box(trie.hash_slow());
        })
    });
    g.bench_with_input(BenchmarkId::new("get", SIZE), &SIZE, |b, &s| {
        let leaves = create_leaves(s);
        let keys: Vec<B256> = leaves.keys().step_by(2).cloned().collect();
        let trie = create_trie(&leaves);
        b.iter(|| {
            keys.iter().for_each(|k| {
                _ = black_box(trie.get(k));
            })
        })
    });
    g.bench_with_input(BenchmarkId::new("insert", SIZE), &SIZE, |b, &s| {
        let leaves = create_leaves(s);
        b.iter(|| {
            let mut mpt = Trie::default();
            leaves.iter().for_each(|(k, v)| mpt.insert(k, v.clone()));
        })
    });
    g.bench_with_input(BenchmarkId::new("remove", SIZE), &SIZE, |b, &s| {
        let leaves = create_leaves(s);
        let keys: Vec<B256> = leaves.keys().cloned().collect();
        let mpt = Trie::from_iter(leaves);
        b.iter(|| {
            let mut mpt = mpt.clone();
            keys.iter().for_each(|k| {
                _ = black_box(mpt.remove(k));
            })
        })
    });
}

pub fn cached_trie(c: &mut Criterion) {
    let mut g = c.benchmark_group("cached_trie");

    g.bench_with_input(BenchmarkId::new("hash_slow", SIZE), &SIZE, |b, &s| {
        let trie = create_trie(&create_leaves(s)).into_cached();
        b.iter(|| {
            _ = black_box(trie.hash_slow());
        })
    });
    g.bench_with_input(BenchmarkId::new("get", SIZE), &SIZE, |b, &s| {
        let leaves = create_leaves(s);
        let keys: Vec<B256> = leaves.keys().step_by(2).cloned().collect();
        let trie = create_trie(&leaves).into_cached();
        b.iter(|| {
            keys.iter().for_each(|k| {
                _ = black_box(trie.get(k));
            })
        })
    });
    g.bench_with_input(BenchmarkId::new("insert", SIZE), &SIZE, |b, &s| {
        let leaves = create_leaves(s);
        b.iter(|| {
            let mut mpt = CachedTrie::default();
            leaves.iter().for_each(|(k, v)| mpt.insert(k, v.clone()));
        })
    });
    g.bench_with_input(BenchmarkId::new("remove", SIZE), &SIZE, |b, &s| {
        let leaves = create_leaves(s);
        let keys: Vec<B256> = leaves.keys().cloned().collect();
        let mpt = CachedTrie::from_iter(leaves);
        b.iter(|| {
            let mut mpt = mpt.clone();
            keys.iter().for_each(|k| {
                _ = black_box(mpt.remove(k));
            })
        })
    });
}

fn create_leaves(size: usize) -> BTreeMap<B256, Bytes> {
    (0..size).map(|i| (keccak256(i.to_be_bytes()), bytes!("deadbeaf"))).collect()
}

fn create_trie(leaves: &BTreeMap<B256, Bytes>) -> Trie {
    let proof_keys = leaves.keys().step_by(2).map(Nibbles::unpack).collect();
    let mut hb = HashBuilder::default().with_proof_retainer(proof_keys);
    leaves.iter().for_each(|(k, v)| hb.add_leaf(Nibbles::unpack(k), v));
    _ = hb.root();

    let proofs = hb.take_proof_nodes().into_nodes_sorted().into_iter().map(|node| node.1);
    Trie::from_rlp(proofs).unwrap()
}

criterion_group!(benches, trie, cached_trie);
criterion_main!(benches);
