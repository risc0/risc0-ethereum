#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod mpt;

#[cfg(feature = "orphan")]
pub use mpt::orphan;
pub use mpt::{CachedTrie, Trie, EMPTY_ROOT_HASH};

pub use alloy_trie::Nibbles;
