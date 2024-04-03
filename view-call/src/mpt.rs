// Copyright 2024 RISC Zero, Inc.
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

use alloy_primitives::{b256, keccak256, B256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, EMPTY_STRING_CODE};
use nybbles::Nibbles;
use revm::primitives::HashMap;
use rlp as legacy_rlp;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error as ThisError;

/// Root hash of an empty Merkle Patricia trie, i.e. `keccak256(RLP(""))`.
pub const EMPTY_ROOT_HASH: B256 =
    b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

/// The error type that is returned when parsing a [MerkleTrie] node.
#[derive(Debug, ThisError)]
pub enum ParseNodeError {
    /// Error that occurs when parsing the RLP encoding of a node.
    #[error("RLP error")]
    Rlp(#[from] legacy_rlp::DecoderError),
}

/// A sparse Merkle Patricia trie storing byte values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTrie(Node);

impl MerkleTrie {
    /// Returns a reference to the byte value corresponding to the key.
    ///
    /// It panics when neither inclusion nor exclusion of the key can be guaranteed.
    #[inline]
    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<&[u8]> {
        self.0.get(Nibbles::unpack(key).as_slice())
    }

    /// Returns the RLP decoded value corresponding to the key.
    ///
    /// It panics when neither inclusion nor exclusion of the key can be guaranteed or when the
    /// value is not RLP decodable.
    #[inline]
    pub fn get_rlp<T: Decodable>(&self, key: impl AsRef<[u8]>) -> alloy_rlp::Result<Option<T>> {
        match self.get(key) {
            Some(mut bytes) => Ok(Some(T::decode(&mut bytes)?)),
            None => Ok(None),
        }
    }

    /// Returns the number of full nodes in the trie.
    ///
    /// A full node is a node that needs to be fully encoded to compute the root hash.
    #[inline]
    pub fn size(&self) -> usize {
        self.0.size()
    }

    /// Returns the hash of the trie's root node.
    #[inline]
    pub fn hash_slow(&self) -> B256 {
        // compute the keccak hash of the RLP encoded root node
        match self.0 {
            Node::Null => EMPTY_ROOT_HASH,
            Node::Digest(digest) => digest,
            ref node => keccak256(node.rlp_encoded()),
        }
    }

    /// Creates a new trie from the given RLP encoded nodes.
    ///
    /// The first node provided must always be the root node. The remaining nodes can be in any
    /// order and are resolved if they are referenced (directly or indirectly) by the root node.
    /// Referenced children that cannot be resolved are represented by their hash. This guarantees
    /// that the root hash can be computed and matches the root hash of the fully resolved trie.
    pub fn from_rlp_nodes<T: AsRef<[u8]>>(
        nodes: impl IntoIterator<Item = T>,
    ) -> Result<Self, ParseNodeError> {
        let mut nodes_by_hash = HashMap::new();
        let mut root_node_opt = None;

        for rlp in nodes {
            let (hash, node) = parse_node(rlp)?;

            // initialize with the first node if it hasn't been set
            root_node_opt.get_or_insert(node.clone());

            if let Some(hash) = hash {
                nodes_by_hash.insert(hash, node);
            }
        }

        let root_node = root_node_opt.unwrap_or_default();
        let trie = MerkleTrie(resolve_trie(root_node.clone(), &nodes_by_hash));
        // Optional: Verify the resolved trie's hash matches the initial root's hash
        debug_assert!(trie.hash_slow() == MerkleTrie(root_node).hash_slow());

        Ok(trie)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Node {
    #[default]
    Null,
    Leaf(Nibbles, Box<[u8]>),
    Extension(Nibbles, Box<Node>),
    Branch([Option<Box<Node>>; 16]),
    Digest(B256),
}

impl Node {
    /// Returns a reference to the value corresponding to the key.
    /// It panics when neither inclusion nor exclusion of the key can be shown in the sparse trie.
    fn get(&self, key_nibs: &[u8]) -> Option<&[u8]> {
        match self {
            Node::Null => None,
            Node::Leaf(prefix, value) if prefix == key_nibs => Some(value),
            Node::Leaf(..) => None,
            Node::Extension(prefix, child) => key_nibs
                .strip_prefix(prefix.as_slice())
                .and_then(|remaining| child.get(remaining)),
            Node::Branch(children) => match key_nibs.split_first() {
                Some((idx, remaining)) => children[*idx as usize]
                    .as_deref()
                    .and_then(|node| node.get(remaining)),
                None => None, // branch nodes don't have values in our MPT version
            },
            Node::Digest(_) => panic!("Attempted to access unresolved node"),
        }
    }

    /// Returns the number of full nodes in the trie.
    /// A full node is a node that needs to be fully encoded to compute the root hash.
    fn size(&self) -> usize {
        match self {
            Node::Null | Node::Digest(_) => 0,
            Node::Leaf(..) => 1,
            Node::Extension(_, child) => 1 + child.size(),
            Node::Branch(children) => {
                1 + children
                    .iter()
                    .filter_map(Option::as_deref)
                    .map(Node::size)
                    .sum::<usize>()
            }
        }
    }

    /// Returns the RLP encoding of the node.
    fn rlp_encoded(&self) -> Vec<u8> {
        match self {
            Node::Null => vec![EMPTY_STRING_CODE],
            Node::Leaf(prefix, value) => {
                let path = prefix.encode_path_leaf(true);
                let mut out = encoded_header(true, path.length() + value.length());
                path.encode(&mut out);
                value.encode(&mut out);

                out
            }
            Node::Extension(prefix, child) => {
                let path = prefix.encode_path_leaf(false);
                let node_ref = NodeRef::from_node(child);
                let mut out = encoded_header(true, path.length() + node_ref.length());
                path.encode(&mut out);
                node_ref.encode(&mut out);

                out
            }
            Node::Branch(children) => {
                let mut child_refs: [NodeRef; 16] = Default::default();
                let mut payload_length = 1; // start with 1 for the EMPTY_STRING_CODE at the end

                for (i, child) in children.iter().enumerate() {
                    match child.as_deref() {
                        Some(node) => {
                            let node_ref = NodeRef::from_node(node);
                            payload_length += node_ref.length();
                            child_refs[i] = node_ref;
                        }
                        None => payload_length += 1,
                    }
                }

                let mut out = encoded_header(true, payload_length);
                child_refs.iter().for_each(|child| child.encode(&mut out));
                // add an EMPTY_STRING_CODE for the missing value
                out.push(EMPTY_STRING_CODE);

                out
            }
            Node::Digest(digest) => alloy_rlp::encode(digest),
        }
    }
}

impl legacy_rlp::Decodable for Node {
    fn decode(rlp: &legacy_rlp::Rlp) -> Result<Self, legacy_rlp::DecoderError> {
        use legacy_rlp::{Decodable, DecoderError, Prototype};

        match rlp.prototype()? {
            Prototype::Null | Prototype::Data(0) => Ok(Node::Null),
            Prototype::List(2) => {
                let (path, is_leaf) = decode_path(rlp.val_at::<Vec<u8>>(0)?);
                if is_leaf {
                    let val = rlp.val_at::<Vec<u8>>(1)?;
                    Ok(Node::Leaf(path, val.into_boxed_slice()))
                } else {
                    let node = Decodable::decode(&rlp.at(1)?)?;
                    if node == Node::Null {
                        return Err(DecoderError::Custom("extension node with null child"));
                    }
                    Ok(Node::Extension(path, Box::new(node)))
                }
            }
            Prototype::List(17) => {
                let mut children: [Option<Box<Node>>; 16] = Default::default();
                for (i, node_rlp) in rlp.iter().enumerate().take(16) {
                    match node_rlp.prototype()? {
                        Prototype::Null | Prototype::Data(0) => {}
                        _ => children[i] = Some(Box::new(Decodable::decode(&node_rlp)?)),
                    }
                }
                // verify that there is no 17th element with a value
                if !rlp.at(16)?.is_empty() {
                    return Err(DecoderError::Custom("branch node with value"));
                }

                Ok(Node::Branch(children))
            }
            Prototype::Data(32) => {
                let digest = B256::decode(&mut rlp.as_raw())
                    .map_err(|_| DecoderError::Custom("invalid digest"))?;
                Ok(Node::Digest(digest))
            }
            _ => Err(DecoderError::RlpIncorrectListLen),
        }
    }
}

/// Represents the way in which a node is referenced from within another node.
#[derive(Default)]
enum NodeRef<'a> {
    #[default]
    Empty,
    Digest(&'a B256),
    Node(Vec<u8>),
}

impl NodeRef<'_> {
    #[inline]
    fn from_node(node: &Node) -> NodeRef<'_> {
        match node {
            Node::Null => NodeRef::Empty,
            Node::Digest(digest) => NodeRef::Digest(digest),
            node => NodeRef::Node(node.rlp_encoded()),
        }
    }
}

impl Encodable for NodeRef<'_> {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            NodeRef::Empty => out.put_u8(EMPTY_STRING_CODE),
            NodeRef::Digest(digest) => digest.encode(out),
            NodeRef::Node(rlp) => {
                if rlp.len() >= B256::len_bytes() {
                    keccak256(rlp).encode(out);
                } else {
                    out.put_slice(rlp);
                }
            }
        }
    }
    #[inline]
    fn length(&self) -> usize {
        // hash length + 1 byte for the RLP header
        const DIGEST_LENGTH: usize = 1 + B256::len_bytes();

        match self {
            NodeRef::Empty => 1,
            NodeRef::Digest(_) => DIGEST_LENGTH,
            NodeRef::Node(rlp) => {
                if rlp.len() >= B256::len_bytes() {
                    DIGEST_LENGTH
                } else {
                    rlp.len()
                }
            }
        }
    }
}

#[inline]
fn encoded_header(list: bool, payload_length: usize) -> Vec<u8> {
    debug_assert!(payload_length > 0);
    let header = Header {
        list,
        payload_length,
    };
    let mut out = Vec::with_capacity(header.length() + payload_length);
    header.encode(&mut out);
    out
}

/// Returns the decoded node and its RLP hash.
fn parse_node(rlp: impl AsRef<[u8]>) -> Result<(Option<B256>, Node), ParseNodeError> {
    let rlp = rlp.as_ref();
    let node = legacy_rlp::decode(rlp)?;
    // the hash is only needed for RLP length >= 32
    Ok(((rlp.len() >= 32).then(|| keccak256(rlp)), node))
}

fn resolve_trie(root: Node, nodes_by_hash: &HashMap<B256, Node>) -> Node {
    match root {
        Node::Null | Node::Leaf(..) => root,
        Node::Extension(prefix, child) => {
            Node::Extension(prefix, Box::new(resolve_trie(*child, nodes_by_hash)))
        }
        Node::Branch(mut children) => {
            // iterate over the children in place, resolving each child node recursively.
            for child in children.iter_mut() {
                if let Some(node) = child.take() {
                    *child = Some(Box::new(resolve_trie(*node, nodes_by_hash)));
                }
            }
            Node::Branch(children)
        }
        Node::Digest(digest) => match nodes_by_hash.get(&digest) {
            Some(node) => resolve_trie(node.clone(), nodes_by_hash),
            None => root,
        },
    }
}

#[inline]
fn decode_path(path: impl AsRef<[u8]>) -> (Nibbles, bool) {
    let path = Nibbles::unpack(path);
    assert!(path.len() >= 2);
    let is_leaf = path[0] & 2 != 0;
    let odd_nibbles = path[0] & 1 != 0;

    let prefix = if odd_nibbles { &path[1..] } else { &path[2..] };
    (Nibbles::from_nibbles_unchecked(prefix), is_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAccount;
    use alloy_primitives::{address, uint, Bytes, U256};
    use alloy_trie::HashBuilder;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn rlp_encoded(root: &Node) -> Vec<Vec<u8>> {
        let mut out = vec![root.rlp_encoded()];
        match root {
            Node::Null | Node::Leaf(_, _) | Node::Digest(_) => {}
            Node::Extension(_, child) => out.extend(rlp_encoded(child)),
            Node::Branch(children) => {
                out.extend(children.iter().flatten().flat_map(|c| rlp_encoded(c)));
            }
        };
        out
    }

    #[test]
    pub fn mpt_null() {
        let mpt = MerkleTrie(Node::Null);
        assert_eq!(
            mpt,
            MerkleTrie::from_rlp_nodes(rlp_encoded(&mpt.0)).unwrap()
        );

        assert_eq!(mpt.hash_slow(), EMPTY_ROOT_HASH);
        assert_eq!(mpt.size(), 0);

        // the empty trie provides a non-inclusion proof for any key
        assert_eq!(mpt.get([]), None);
        assert_eq!(mpt.get([0]), None);
        assert_eq!(mpt.get([1, 2, 3]), None);
    }

    #[test]
    pub fn mpt_digest() {
        let mpt = MerkleTrie(Node::Digest(B256::ZERO));
        assert_eq!(
            mpt,
            MerkleTrie::from_rlp_nodes(rlp_encoded(&mpt.0)).unwrap()
        );

        assert_eq!(mpt.hash_slow(), B256::ZERO);
        assert_eq!(mpt.size(), 0);
    }

    #[test]
    pub fn mpt_leaf() {
        let mpt = MerkleTrie(Node::Leaf(Nibbles::unpack(B256::ZERO), vec![0].into()));
        assert_eq!(
            mpt,
            MerkleTrie::from_rlp_nodes(rlp_encoded(&mpt.0)).unwrap()
        );

        assert_eq!(
            mpt.hash_slow(),
            b256!("ebcd1aff3f48f44a89c8bceb54a7e73c44edda96852b9debc4447b5ac9be19a6")
        );
        assert_eq!(mpt.size(), 1);

        // a single leave proves the inclusion of the key and non-inclusion of any other key
        assert_eq!(mpt.get(B256::ZERO), Some(&[0][..]));
        assert_eq!(mpt.get([]), None);
        assert_eq!(mpt.get([0]), None);
        assert_eq!(mpt.get([1, 2, 3]), None);
    }

    #[test]
    pub fn mpt_branch() {
        let mut children: [Option<Box<Node>>; 16] = Default::default();
        children[0] = Some(Box::new(Node::Leaf(
            Nibbles::from_nibbles([0; 63]),
            vec![0].into(),
        )));
        children[1] = Some(Box::new(Node::Leaf(
            Nibbles::from_nibbles([1; 63]),
            vec![1].into(),
        )));
        let mpt = MerkleTrie(Node::Branch(children));
        assert_eq!(
            mpt.hash_slow(),
            b256!("f09860d0bbaa3a755a53bbeb7b06824cdda5ac2ee5557d14aa49117a47bd0a3e")
        );
        assert_eq!(mpt.size(), 3);

        assert_eq!(mpt.get(B256::repeat_byte(0x00)), Some(&[0][..]));
        assert_eq!(mpt.get(B256::repeat_byte(0x11)), Some(&[1][..]));
        assert_eq!(mpt.get([]), None);
        assert_eq!(mpt.get([0]), None);
        assert_eq!(mpt.get([1, 2, 3]), None);
    }

    #[test]
    pub fn mpt_extension() {
        let mut children: [Option<Box<Node>>; 16] = Default::default();
        children[0] = Some(Box::new(Node::Leaf(
            Nibbles::from_nibbles([0; 62]),
            vec![0].into(),
        )));
        children[1] = Some(Box::new(Node::Leaf(
            Nibbles::from_nibbles([1; 62]),
            vec![1].into(),
        )));
        let branch = Node::Branch(children);
        let mpt = MerkleTrie(Node::Extension(
            Nibbles::from_nibbles([0; 1]),
            branch.into(),
        ));
        assert_eq!(
            mpt.hash_slow(),
            b256!("97aa4d930926792c6c5a716223c01dad6b64ce11ac261665d6f2fa031570ad26")
        );
        assert_eq!(mpt.size(), 4);

        assert_eq!(mpt.get(B256::ZERO), Some(&[0][..]));
        assert_eq!(
            mpt.get(b256!(
                "0111111111111111111111111111111111111111111111111111111111111111"
            )),
            Some(&[1][..])
        );
        assert_eq!(mpt.get([]), None);
        assert_eq!(mpt.get([0]), None);
        assert_eq!(mpt.get([1, 2, 3]), None);
        assert_eq!(mpt.get(B256::repeat_byte(0x11)), None);
    }

    #[test]
    #[should_panic]
    pub fn get_digest() {
        let mpt = MerkleTrie(Node::Digest(B256::ZERO));
        mpt.get([]);
    }

    #[test]
    pub fn hash_sparse_mpt() {
        const NUM_LEAVES: usize = 1024;

        // populate leaves with hashed keys and RLP-encoded values
        let leaves: BTreeMap<_, _> = (0..NUM_LEAVES)
            .map(|i| {
                let key = U256::from(i);
                (
                    Nibbles::unpack(keccak256(key.to_be_bytes::<32>())),
                    alloy_rlp::encode(key),
                )
            })
            .collect();

        // generate proofs only for every second leaf
        let proof_keys = leaves.keys().step_by(2).cloned().collect();
        let mut hash_builder = HashBuilder::default().with_proof_retainer(proof_keys);
        for (key, value) in leaves {
            hash_builder.add_leaf(key, &value);
        }
        let root = hash_builder.root();
        let proofs = hash_builder.take_proofs();

        // reconstruct the trie from the RLP encoded proofs and verify the root hash
        let mpt = MerkleTrie::from_rlp_nodes(proofs.into_values())
            .expect("Failed to reconstruct Merkle Trie from proofs");
        assert_eq!(mpt.hash_slow(), root);
    }

    #[test]
    pub fn parse_empty_proof() {
        let account_proof: Vec<Bytes> = Vec::new();

        let mpt = MerkleTrie::from_rlp_nodes(account_proof).unwrap();
        assert_eq!(mpt.hash_slow(), EMPTY_ROOT_HASH);
    }

    #[test]
    pub fn parse_eth_get_proof_existing() {
        // { "id": 1, "jsonrpc": "2.0",
        //   "method": "eth_getProof",
        //   "params": ["0x0000000000000000000000000000000000000004", [], "0x12962D1"] }
        let value = json!(["0xf90211a064fba17f021dbb0322d3e7d30aff9db628377c960f1ebed87701f08ce0b040eca09d91529d0a9cfb8e091b206bbcc359f7734dff6815c73e65ecbec4063508f9e9a0558f96de53974dabf223c2501c08c97dfc1c3d47a9b2c4ea0655df221c8154bea057fbe18660f4919b33d1dfbccd340a3d9ddae1a0e7d7df6f8df4b3cbe7c9d875a084f9dc2615d641d4136337942a7c76b94164b4ebd29422b860fa2251f82d2b73a05b6b9d6d421156c0282dfe73491c8754906849e989210d766fe4e4e266b32605a024eb3df5b1a9d8c6e40fb604542bc70e38e33f32c0f2feebdbd9b7e7e31ba7e4a015935675b64554bdc16b1c1cfc25c89f5d284ff11dcfbf7993aec54a92f0bba4a0099d5fc449ccc8c39482564ac0dd831f1e05387dae9dfd9dea51cb0d4e19aa8aa031d64c42ebfbcecb9f0220b752ab56f06b2682778d17119b7324c0ad96dfc149a0095fe3791c69f53ed524f8edbea71ac57efd64b9198810cc763efa0f4a5c2897a0515238447863a22615f154bc9c72e3aa4f69c4726ff41063a467ae84416731aaa022f3633a252b9b64f1bfcf48fc267570bd4203e4f36feb85dded2c1bd1cff3e0a042d3afbd98a8965f366b72e2213895467a77159c1c3d28c84a29013f8cb12873a07fd2b3663f9fc8d7836096d9369a233eb17532e85e69a953011f7d698b2cc00aa0726b3dbf33d6ad6a58d3c6007a706bbcba5442ad17eda4dd1934fe40279ad71080","0xf90211a0f5271d0b41d27321301a4a99ee222e2f6993733b8bb4297e5f4a193309cea441a0308c36c27bc35ce53fa864873bbdda24f8dda698a8829976c654d71aed28d65fa077780501dffccc355bf0353e3641740ba33c12291c4a8f2a240c7c5e8c0f0ddaa0d571e89fdf190b87f84db4bf25b50648758b6d86940e172622b93c6e818ca4dba076419b70cc41744498d74746de84ef31ae62a324a60cfcb9f38b438e31c9325ca0d41cdf14b7a848eb7b90d53aecee8b656bdc4f21f1285b40075fc2cfb09970dca0d268e7c26b2bf55597f7f2e6b1783ff59468590ef813e2d0c941c545ac947093a0aaaa06235ff457fc16692855eb8f6417895e85ee99030273e67ed434ec9edc78a093176f5004283b61b43c5bc0ac81a64d1f8fa13f03151040c25f0687fd661a20a01875442e8e36fb90a38cfe7fbc47071e6a8d73afe31310167facf68f13428509a0e964058555501ab03129574589ec66fbd34af7af4f9ede88dd20e6d509d3ed78a070094346b748e0d7fe73f52655307fed3967a9b8b5d12abcb86baa338bfce384a07b944e9ffc124854852a026deac8105902cb9bd96bd45ee6548566fcd9d0280ba0e9ec860d689a8471762d8bbacdc453de018634b0d80aed35eb0f72e5d0b4f841a0fca2e3962d69a6927845d1537f58b3871ea19e775ac88b973ffa7717c9f9b1dba0c3ef3351fb2e76a5130b103ee85d83a7fc658fc306d43d29a016f8e696b412db80","0xf90211a07a0bc6ce42efd1947af01f6573b633c431a5b0d14fd22e0704cb8556b7098fd3a0105680327ae064d660fe790b6bbb4f1453d6188eaafd707b2d0be6010275b3a6a0b41d2058d4c85808c887fd70c07ed2629c9f5f138d8dd512c060de9b07d2cd18a0639cbfec697a3c8461f4dd0f0eda8a58cb186db9dd6831d0d0a3ce9c6f99a7fea0a9f7964dec293389bc37f594cb03be415ec76208081bd61aa56bb83b8e749d1da0541091360f807b91263b692989e1a2df1aa894568661ea88359fd0ad76837131a02bea3a3d833e46c77b3214e753f59157d232d5f1c4d9f1b936e82f343ed62f48a07d6282c3a3353eaba6503faaa91c2efe85d5c72a80d209ad2c2648ea24449b7ba0c0576e98237780fea7677ef30e5e5b966f8874d2defa0f4e2bc95ac6e3180ffda0514d5942624e2309086cfde5c70cce77a13d3d8c7e04a299d9c98d4bd76fc80da0267e7598bb09c5965509b91763d4ddf7eb8baaa19276ef1630ff904ba22c5836a0a18ede2979de3c02978dbf1542c517a3eb42fe537fde09a3fb0ab46e139d0712a066b2679d23b911ea309551b9453115ae26d92fd05f8ac3f2e2e6e31cf6ac9dc7a0d541bc04f0feaa8bd4239d25cb04b1ddb5976d65a20bf91eae810f8a8fc33bdaa0d75b751ed0a1ef82c9cae91b2e97ea78c218d9a8923be953753962ef81b1aa9ba0cc3d9261f5ba93857bdac0d26a341984b45d3a6aa38811e4ced7a12594722a9380","0xf90211a028e51fc851a6315210c3e973bc0c37db45b9cbc38384235414e7f83bd06097f9a04fddedaebfa0a6e8f6bc1c035ff20c0365a92911e8a9b6f267621f729461fa68a0a2a92894c4f4f64cd8563f2c5945b3fc2857ec60bce8549d5871966510234310a00f8ec60cdce60eca2287e2c08b6a074cec1218b355e08504f8e0209095cf2caaa0a7f6689140ac7d1230f773d0e7f395c884d4c4be8e19c752650e94d59e63d492a061dfe74f4e14f2a06dfeb9f268acd81559c4ef17de098630432b2ff342441c36a00c450940c088ad97119ac6b9ecef673ccc41c4244bffac10744bdd2868811f15a09d405cc6b538d9a9033a96818608fb801d4f1a4319448e459a802aa966f0637ea0a604db8246efa1a62859269ff28709d950d74b55b4730002c5639e383a2867bca0f11de25a06de0a1162bffb3d400edf07a64659aa59c3554898700082866997fda02454c86901086b11a1b11a0f7ed300aeb451ca9d50509f7f8d1818cdaa42177ba00b06fa9d11f507136397be1aa73ec37c8bf8a7b10d1ccd07d0bcd9634ce469d0a001e5be1f99d16e7b0f12d73d01c7aa54e109186b18c7c1eb04a6784d619ca452a0676f68104f74c5f03d7b4638bbbb9a0ec647f34ae489de642eb9fa6c03388e20a048b07679ba600363323c2304443d2815ebe87e64bcee9f5ea31d97a0c4720c95a035d02f8a26fb9926254b3309ac3cacb94852a9a7469ab094e12b8df2d820dac680","0xf90211a0af5538b1a07c6b743b04ed3a04d1b20db89c831e2f2acfd54d92f710004c9495a0c3abf984d9d723ec0aaa2d2c6afb75b693ddbd5538a0709bbc17f8b17325b78fa051d2081439320734f889a4de79d72ec9d009bdd7b33c1d2970cb88c98d13d4c6a0b55856ee040bc79be42aa48f807651502a07ea73d46a63d2997a5ee1493b3372a0df7a231010a67f2286fbcc6e9347e0f0d7706bc23a95a08342d61c9f83eb93a8a07c0dd78b4a5a44ad1fb26fb11c710f8478f039b89df1f6c888d1b984bf51338ba075367e67992101f00c0d4ac7b90110c901ba1dc0bff377084ec3c933643019a3a0ecbb4272ff5b494973deb3ea559bd5296c0de719b6cbc71d4469dd1b0697aa87a0441af491d98cf36d5c259ad8a183348aba1f642a6c5d408c846d09f86b52882ea083641f2add799b0244eeab16095698b801dad630a60a769fb3f378346514f44ca05829539f9d1d5835d74a994278ff03ede1fde23997a2d4bacaf7a74c7081308da038b4f88c187767463cac005228d458a26554fa28174a82b2d6ea47a86991f026a08f9bf87dc8b2cfae0f21ee5e300b71310b5092268921ea387ed4d1d68ebb47c2a0b1a29582a77306d0a48675f4ee4603f01b3744993d1b057592c0b4af91ed5c73a065cc8133f26ec26a0053f978068a41075b138f7cd077452832f7fa1c79ec2250a08b3561166e1256df806bc6ba3c7f6312493b38133aa3524f51884b9115c7cc9780","0xf90211a0000aba28e5abf987658d245aabf1157eedee3f099ebf95affabe5a1e9b53b521a0c37da1b511fc6e5925e9b3e6870866da39bd3a880b45b3d830dacddd5ca5d1c1a054eb2e6cd765137c3ebde36d30decd3a9461e9245ac510405740a1307f700f8fa009b3401df44a885d6ab901ba7b789b290f7c3fbbdb2739ab487e33ff48bb6f13a0b124c2c227b22040df405b92eeeae70b28f9f59cb355220a0184c2d26aebf765a06f9217b6b53f3258db8c9b91cd05a07d2e90608c490e76dff6a847a7ead45859a00007fd17fdc3326a80364d9e820ca33580fa9e4641c3d9864a653c90515e3255a0110ad882ed1c35d31bca099524ca8da2aec305bdcc02cbee38f986f3bbfd6946a0d1a7c39603704486613fe6a83d8fff219e1b4d71cecd01b460703f4d0c4fee26a084a158747da12a4c0e1df62f95b206779f6da199a9832d22f79cc6017b14eeb5a070dbfff894a8269d76bb53722185466c879eb601fd9b6c413ef69f8b282959a8a0ac026666c540c02a02838e725f62a41356e6617ccf16a930db35ad4b253253c2a001c4c0478fdbaadc5ad58defe18fb9df49bdd12c9b8efbe7acfb11bd8deb52eaa0637e3ebb17f8bf5e8e9d2a987e00a10070cd8a8623d327fdd0fac545e453000ea0052155fc9e62a4a89b260a55f0d470b91b1e009dc8923292284f260a9ecf8785a04fb3083fdd53a3023fc4aec62f307f7e87cf0e4a771fba42cbe62a10ba98f40a80","0xf901b1a0d3c18050bdcb55f8e919d224eb69062be67a76708fb45d5f4263e2bf26473339a08c8749c75e158292e70ecf6defbd039c5b739733db1105430b065c3d40dbafbba02a33fef2d0dc98049fb6e1ab176ceef4cf4a376a62d9076e4557618200b3c00ba0534f68319d219b17e6c94295329c3a85478d182591e721dcb82ade11212e8ab2a0a4b88347eb9d7466e1cd2b7025a14bc53b93e39532fb60e276f24ce64f43080ea0c3b3a7be7982dcbb5680948ec6e80103109bb7adb312d6f738870894c0cd7cef80a007e513f4512674cfc773e861e6a34250eae5508f5a24b1af07e62583eecfc675a0f501c13e330dd417836ad1a304a578575b4618880a479b542953248c4aaef3bca0a5d05faed975c0134a4333809d471a6afb7b19f7db1a2e928ec0e27b5e5cf651a0f90433f3b2fa2fae1df8ce6b1c2cd794fe4fd8f899767d9aa59607285efbe17f80a0f2d6a5c820099a8212b3af56264bda3b519af5379f1a09f2a6e6dc412a1e6561a0c82e9f321649f50e95a89db8fbdec55babc1a552850ee7fff4d22d9aecb5710f80a0c189cfed2417dd103f87679e16d3c8e178d61d5da36bbdb2aeb4aa170a1560ba80","0xf85180a0c3b71af926a3b464d43b79c4f3b91835b055202902801ec32940cd45d78c3ed3a06d11221db3e0db5015e8b8c4f2e738c733a0b212a1399021e7824e5f908ecf578080808080808080808080808080","0xf85180a0cce18d0d1d7b4befb137e8b893e0d62e61cc7e43474d885853697bc6729e6544808080808080a0b17e5bdc4a7d0f184dde26b3a718143439522942254dd9bd109255cc49d3b0ab8080808080808080","0xf86d9c3a393dbd067dc72abfa08d475ed6447fca96d92ec3f9e7eba503ca61b84ef84c80881a5fd46f92e55070a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"]);
        let account_proof = serde_json::from_value::<Vec<Bytes>>(value).unwrap();

        let mpt = MerkleTrie::from_rlp_nodes(account_proof).unwrap();

        let address = address!("0000000000000000000000000000000000000004");
        let account = mpt.get_rlp::<StateAccount>(keccak256(address)).unwrap();
        assert_eq!(
            account,
            Some(StateAccount {
                balance: uint!(0x1a5fd46f92e55070_U256),
                ..Default::default()
            })
        );
    }

    #[test]
    pub fn parse_eth_get_proof_nonexisting() {
        // { "id": 1, "jsonrpc": "2.0",
        //   "method": "eth_getProof",
        //   "params": ["0x0010000000000000000000000000000000000000", [], "0x12962D1"] }
        let value = json!(["0xf90211a064fba17f021dbb0322d3e7d30aff9db628377c960f1ebed87701f08ce0b040eca09d91529d0a9cfb8e091b206bbcc359f7734dff6815c73e65ecbec4063508f9e9a0558f96de53974dabf223c2501c08c97dfc1c3d47a9b2c4ea0655df221c8154bea057fbe18660f4919b33d1dfbccd340a3d9ddae1a0e7d7df6f8df4b3cbe7c9d875a084f9dc2615d641d4136337942a7c76b94164b4ebd29422b860fa2251f82d2b73a05b6b9d6d421156c0282dfe73491c8754906849e989210d766fe4e4e266b32605a024eb3df5b1a9d8c6e40fb604542bc70e38e33f32c0f2feebdbd9b7e7e31ba7e4a015935675b64554bdc16b1c1cfc25c89f5d284ff11dcfbf7993aec54a92f0bba4a0099d5fc449ccc8c39482564ac0dd831f1e05387dae9dfd9dea51cb0d4e19aa8aa031d64c42ebfbcecb9f0220b752ab56f06b2682778d17119b7324c0ad96dfc149a0095fe3791c69f53ed524f8edbea71ac57efd64b9198810cc763efa0f4a5c2897a0515238447863a22615f154bc9c72e3aa4f69c4726ff41063a467ae84416731aaa022f3633a252b9b64f1bfcf48fc267570bd4203e4f36feb85dded2c1bd1cff3e0a042d3afbd98a8965f366b72e2213895467a77159c1c3d28c84a29013f8cb12873a07fd2b3663f9fc8d7836096d9369a233eb17532e85e69a953011f7d698b2cc00aa0726b3dbf33d6ad6a58d3c6007a706bbcba5442ad17eda4dd1934fe40279ad71080","0xf90211a07c0b2ddf03d5254f0a71793b61268dcccbcba1bbf91f84e1f01dfc7e748a22b3a0d066cbf287fff296cdf1c8d672f64cd1c7b582237a0e56f5523cadc9fd02db99a0ef75b0e082af37853216e2f1e189e8ed4a8fd8597d4cafb6a009d593d149463ba06b26667374d83ee094dab3adf971df2e3ec3f8255ce8e34b73d89afad4e5cc2ba0cc64a85fd14a5b27ec9aecd563395ea1c34629c7dca53222e7d19d1213af4d6ca07e3b3fd39452db1f8da9316152693d688505eff731e8b9c0e4512ba4a7882bcaa03579517fa320d080a74555da75ea17e676486aca21cac482f5f90993acec7112a0d674f6623ec3aaccde4856376e52b439ef4ebec600903c1e554b908b97780f64a04ebcd669406c6e48c0d1eca18c6c4040c8af886eac25e7218ef48d4cac8acf2ca0a4136773e1fdbde71ac578c4f5d25ee1c23067c20b43ea539b264fd566920630a0e94cab7b03de5bc128c5a15f3058c3c5ebebdd6f16e17548c2669886c1221b7aa0b1716052ef9a44fee9c985c4a957961c6d389bf290c82338e82cde8de5b174d5a096a699c048dc1d20509738881a99f1a09bc83a9ec0730b763c81c7ffb300b744a0733197a2479190e993f9da804810515c0e07b5752a1d0e537856cca86212a0f0a0d89157cef32fad06a43dd3ee54094a9790632d68cf07468ded845212ad484338a06055bbdb3664389c6e66a1519e99e802cb450d78fef9b8f8397c400d915ffe4780","0xf90211a001caaac143549f9bf7006ea276d133e2c6830bdb68d16a294a8aa836eeff19a2a0a68cdb682f254b8d8dfaf054bd571f4a84848cd58182274278c6dc09269093aaa063b4ef8b826676cea42d875d5a917193003ca99863a28dd4e4532307964c7e86a084473c41238e3dab60c7074c0fe4d6b14fec21124bdb999ef9fe92675d9e47bea01093a60823539cb5598a972ae1626dc68e62b83306cd0a7d0ca35bb0ae095432a0ea97146fe913ab3ffa242230eb2b0034f883de2a946f615cf4b152d8e4f9c2f1a0600c57157158dda437fdb93a2902d5a6aaadd2c4c4ef781b0f3bb9db52589ff1a005cd22b0467087c13203f302bd75ee3a49a4f50f72f044c510dfb80c5fd73d08a01a610490b54f297f9ed7f86993b19a4f1fe481d0bae5f8cc36428b066a19f675a002591f7ca3e129662132c3c43abec639309c7276bcb93f056ae0e064b08e544ba04cff311608aad7f75fe8660422dea95de1299b59ea1a92bc090a88c0a85033a1a0a23bc8dbe3fa661f80a211fbe0d46b938d681ed5c218391d1fc078242c52e07aa05152a90bb3bf83bc20c79d41e21eba4128916e93e3b2aa44e91d66419fed631ca04b9939df74f3585051cc7a256316931e8bbdba7ffadd42fc6a526acea2a65d5da0ad62bdb2eafbf12a569ab87cb4afd20853fd749a14817501bc051e16ace4b31da032a623bd0d0e0866790c76333c7279c455723c6c878d0a45767f9dd590f6f82b80","0xf90211a070740fa5e0ff39e4ecaa3807014386782670ead0ca3930db6e201e0633883524a0fae359c9f3636a34addbd37e75822169ddb824795f59a422a663466feabde3fca0ae96a399523295fb7628aa987c92c324aa579f7a6a0ef3215924f5ab0e2c7785a08b997d1e84063ff2b49c6fc7dda806333bec8a5616475b35021dc7330a6e63f7a076379dbbac470d9f0f8752f363dbb2dff2a0c0e1028d0a5d9aacdf5b735e9d4fa0da495111c40fed1ec3f6ae187ef71a8536a4aa6c09e84720f3645f1967267474a081250ce896356ce835178ed98f1b848a5b4c832f32c113e235020910437adcdba03d5338d4eb62c4d1bad3120bfff7c202a54c365abf2324ad0d97a04077b76900a03fea24d162e9725dc5e204fa2b8db528d0fc21ac54aa9c94e15105053e7bfd24a0c0f751477ad4b3a51a0af066821259e1a6ad3ac4a515c761765dd69552d07abfa079824c28b22d7b33105663cb8520d62101e303e9a0fabe00dfe2598654559b02a04be5cf039ac5c1bb6f8a4bf5dc3ceaa55e8e3fa8a9f6ae1953f744ef8c4c312ca0924250c41261da55a231889b7e88ff81428734661112d4faaa2961623ddd607ba0952fe6d321af6a7c322180c15f6aa06a8e3a461068f0e8c08183fd7536f9fd08a00b47228191943da98cc93b06f2475cb33de07d12d1445be308ffd94d786df047a0befcc93acb07cdf6240f884f7b4064f238c55f997a517f4bfcf6b970ea100d4e80","0xf90211a035ab3b8892330b5d3a92328b1c739c931c357dd4a5dc03e97ce130eb4d6ecf88a02ac2040a3839d2addee3deea351e02549e1a6662a5ff0ba42b8da6fd8964d58da0d5bef1786b6c185e65857742a860b724cba879fa0e8ae58abfab97e9ba213cc3a0649a68c768383bd53cd4b633b5297046bd8bf5c8b5e3f7be38b9b7eb037028e2a0247f186e30f069ed59215d7ed366c311a5bc5bde30ba52a8decc1d9145dcf286a0a725755aa59c849d7896625bbe2f31e0df98158be40adc6a394ffb1b4c05edcaa028a1af512637cfa63d06d9a416c46c6c8823be383a1ba1c1f880ade56b857ae6a070c12456255d06936ff8279cd8ed2de4596ff666161b8519fe8467310e88318fa033dfb37033f44cdce425c078ebe9f8ceb083f2bdb2058409c51c724140c4e99da0e38a0e9efc642da0375974ce69672ade21c5d43703ea5a38ad69644ccd01dc05a0f0773bd08b76b985fb3add2bf308fd1c548e22acb7eae8375f01f4c163f76be8a0e9cde81fdd404fb391b8ba5b3446e8c2e013b7792bc80f77703f2753552f470ea00975fa52a240800fd50ef22dad2aba6d1b4aeb19ee580ca13640d8a6de0936b9a07dd0437de64d7b5053478116ba0447ee5181818aadfb4a00ea1df67cc5d0bd1ca005f923facc0fb4445a5a488f628b353f3eb89936fb9e6b29bb1882e5c0881907a01d4fb8aac5a8d71ac5c0ed0c4491aed1532551451f630d717809797b4c3423b480","0xf90211a011d5405f5bf3648db2730954e75f7562daf4f93ae301482f3de752db8c6f6633a0f5dfe0e59a8b701cc7255480aba875bf4b2f8ec2b2a75b40320989d061f239ffa0641476041254ae3679696731e89da6e8ac4edc30762b30f0237014db2097ca98a0bca8b92c364aa974060a83482b3fddcbda788ace19d249e24225eb91cea050e3a08d5bc061d99b9803d93ad307aefb95950a9e5092cd3de0d642ec6b78d47ff883a093950c5e2655b226fccfd19359302b4e5a19e0d4812dc4859b0eadb3ee984118a02cc1641e3a8f95cea933cd6486d30e8d78d4a33fc81660b580ab05a67d13e438a0e9a7107962410d730bbc8f2350edbb592e7fb741dddee692c4bd9d4b3f1c16b4a05de66765b606c7bce1889f7c55028d19187f9ab9096e4d1927de1376c5905f2da03ca1622b70663d6880d0470191a28805547888ee1ece7ac65fd5c77dc67f6489a0cb515b40517b5c150115cdc0de89ed0e2a962a1ccdea09863b84050406fbd3eda0ff490436b20b1c8113eb98909c82c268e5454c8092ba0bc48a2b2903a0b4d372a07798003e5b7c0a905f0920e98bb17cf0a7f66fde92b0dd356463976cdda8c2e4a00c0fa4a0181bb622b9a4073844d5a72853b21e78db968ad4cea027828d402169a06b227ce534153d2d3952d3085da4f747e1c647f43ee616774df6f50c3f5646e5a0964a937d6cb948eaee92f05bd1a9d03af8ea3ee4e68b02ca9644d96ad86a0cd880","0xf901118080a02c5fbef8c93de59996332553693c43cf28dda1d13ac91dbee861a720883c7301808080a00cafef025cf50981161339913df13fac3635bb4d4612a6779b992b0896c1779480a0ad841e530360d785f7f258c646148f4b51093724f3b769efbb621fee609d2c3aa00abab5bb26960da6d85071fb6f12cf052c70b61c53acd72558ee06048a532128a043ae5b927740bbb05d9e6643a5c2e8c473cef67e529d431faf6edc79d19ba78a80a04a8ad4e57fe8d09e8596dc5131380ea3068decd740c1641ff712b35e37d6586980a045bd253469234b741abe3c8b110c04b0b9f3f983f752c394ef77814351a8d1bda08f74385b8385a4ebff237231c67a623e7bbad8151654e9edf32fa8464802cc6a80"]);
        let account_proof = serde_json::from_value::<Vec<Bytes>>(value).unwrap();

        let mpt = MerkleTrie::from_rlp_nodes(account_proof).unwrap();

        let address = address!("0010000000000000000000000000000000000000");
        let account = mpt.get_rlp::<StateAccount>(keccak256(address)).unwrap();
        assert_eq!(account, None);
    }
}
