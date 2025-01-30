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

use super::{
    children::{Children, Entry},
    memoize::Memoization,
    node::Node,
};
use alloy_primitives::{
    hex, keccak256,
    map::{B256HashMap, B256Map},
    Bytes, B256,
};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, PayloadView, EMPTY_STRING_CODE};
use alloy_trie::{nodes::encode_path_leaf, Nibbles, EMPTY_ROOT_HASH};
use arrayvec::ArrayVec;
use std::fmt;

/// The length in bytes of an RLP-encoded digest, i.e. hash length + 1 byte for the RLP header.
const DIGEST_RLP_LENGTH: usize = 1 + B256::len_bytes();

impl<M: Memoization> Node<M> {
    /// Returns the hash of the node.
    #[inline]
    pub(super) fn hash(&self) -> B256 {
        NodeRef::from_node(self).hash()
    }

    /// Returns the RLP encoding of the node.
    pub(super) fn rlp_encoded(&self) -> Vec<u8> {
        match self {
            Node::Null => vec![EMPTY_STRING_CODE],
            Node::Leaf(prefix, value, _) => {
                let path = encode_path_leaf(prefix, true);
                let mut out = encode_list_header(path.length() + value.length());
                path.encode(&mut out);
                value.encode(&mut out);

                out
            }
            Node::Extension(prefix, child, _) => {
                let path = encode_path_leaf(prefix, false);
                let node_ref = NodeRef::from_node(child);
                let mut out = encode_list_header(path.length() + node_ref.length());
                path.encode(&mut out);
                node_ref.encode(&mut out);

                out
            }
            Node::Branch(children, _) => {
                let mut child_refs: [NodeRef<'_>; 16] = Default::default();
                let mut payload_length = 1; // start with 1 for the EMPTY_STRING_CODE at the end

                for (i, child) in children.iter().enumerate() {
                    match child {
                        Some(node) => {
                            let node_ref = NodeRef::from_node(node);
                            payload_length += node_ref.length();
                            child_refs[i] = node_ref;
                        }
                        None => payload_length += 1,
                    }
                }

                let mut out = encode_list_header(payload_length);
                child_refs.iter().for_each(|child| child.encode(&mut out));
                // add an EMPTY_STRING_CODE for the missing value
                out.push(EMPTY_STRING_CODE);

                out
            }
            Node::Digest(digest) => alloy_rlp::encode(digest),
        }
    }

    /// Memoize the hash of every sub-trie.
    pub(super) fn memoize(&mut self) {
        // early termination for already memoized nodes or Null/Digest
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache)
                if cache.get().is_some() =>
            {
                return;
            }
            Node::Null | Node::Digest(_) => return,
            _ => {} // proceed to memoization for other variants
        }
        match self {
            Node::Extension(_, child, _) => child.memoize(),
            Node::Branch(children, _) => children.memoize(),
            _ => {} // no children to memoize for Leaf, Null, or Digest
        }
        let rlp = self.rlp_encoded();
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.set(RlpNode::from_rlp(rlp));
            }
            _ => unreachable!(),
        }
    }

    /// Returns the RLP-encoded nodes of the trie in preorder. I may return duplicate nodes.
    ///
    /// Each value but the first, represents a node with RLP-length >= 32, while shorter nodes are
    /// included inline.
    #[allow(dead_code)]
    pub(super) fn rlp_nodes(&self) -> Vec<Bytes> {
        fn rec<'a, M: Memoization>(node: &'a Node<M>, nodes: &mut Vec<Bytes>) -> NodeRef<'a> {
            let node_ref = match node {
                Node::Extension(prefix, child, _) => {
                    let (path, child) = (encode_path_leaf(prefix, false), rec(child, nodes));
                    let mut out = encode_list_header(path.length() + child.length());
                    path.encode(&mut out);
                    child.encode(&mut out);
                    NodeRef::Rlp(out)
                }
                Node::Branch(children, _) => {
                    let mut list = Vec::with_capacity(17);
                    for child in children.iter() {
                        let node_ref = child.as_ref().map_or(NodeRef::Empty, |c| rec(c, nodes));
                        list.push(node_ref);
                    }
                    list.push(NodeRef::Empty);
                    NodeRef::Rlp(encode_list(&list))
                }
                Node::Leaf(..) => NodeRef::Rlp(node.rlp_encoded()), // do not use the cached value
                Node::Digest(digest) => NodeRef::Digest(digest),
                Node::Null => NodeRef::Empty,
            };
            match &node_ref {
                NodeRef::Rlp(rlp) if rlp.len() >= 32 => nodes.push(rlp.clone().into()),
                NodeRef::Cached(..) => unreachable!(),
                _ => {}
            }
            node_ref
        }

        if matches!(self, Node::Null) {
            return vec![];
        }

        let mut vec = Vec::new();
        match rec(self, &mut vec) {
            NodeRef::Rlp(rlp) if rlp.len() >= 32 => {}
            NodeRef::Cached(..) => unreachable!(),
            node_ref => vec.push(alloy_rlp::encode(node_ref).into()),
        }
        vec.reverse();

        vec
    }

    /// Creates a new trie from the given RLP encoded nodes.
    pub(super) fn from_rlp<T: AsRef<[u8]>>(
        nodes: impl IntoIterator<Item = T>,
    ) -> alloy_rlp::Result<Self> {
        let mut iterator = nodes.into_iter();

        // the first node must be the root
        let mut root = match iterator.next() {
            None => return Ok(Self::default()),
            Some(rlp) => {
                let mut node: Node<M> = alloy_rlp::decode_exact(rlp.as_ref())?;
                node.cache_set(RlpNode::from_rlp(rlp));
                node
            }
        };

        // compute the references of all the remaining nodes
        let (lower, _) = iterator.size_hint();
        let mut rlp_by_digest = B256HashMap::with_capacity_and_hasher(lower, Default::default());
        for rlp in iterator {
            rlp_by_digest.insert(keccak256(&rlp), rlp);
        }

        // return the resolved trie
        root.resolve_digests(&rlp_by_digest)?;
        Ok(root)
    }

    /// Resolves all applicable digest nodes with the node corresponding to the RLP encoding.
    pub(super) fn resolve_digests(
        &mut self,
        rlp_by_digest: &B256Map<impl AsRef<[u8]>>,
    ) -> alloy_rlp::Result<()> {
        match self {
            Node::Null | Node::Leaf(..) => {}
            Node::Extension(_, child, _) => {
                child.resolve_digests(rlp_by_digest)?;
                if !matches!(**child, Node::Branch(..) | Node::Digest(..)) {
                    return Err(alloy_rlp::Error::Custom("extension node with invalid child"));
                }
            }
            Node::Branch(children, _) => {
                for entry in children.entries() {
                    if let Entry::Occupied(mut entry) = entry {
                        entry.get_mut().resolve_digests(rlp_by_digest)?;
                    }
                }
            }
            Node::Digest(digest) => {
                if let Some(bytes) = rlp_by_digest.get(digest) {
                    let mut node: Node<M> = alloy_rlp::decode_exact(bytes.as_ref())?;
                    // do not try to replace a node by a digest
                    if !matches!(node, Node::Digest(_)) {
                        node.cache_set(RlpNode::from_digest(digest));
                        *self = node;
                        self.resolve_digests(rlp_by_digest)?;
                    }
                }
            }
        }

        Ok(())
    }

    #[inline]
    fn cache_set(&mut self, rlp_node: RlpNode) {
        match self {
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.set(rlp_node)
            }
            _ => {}
        }
    }
}

impl<M: Memoization> Decodable for Node<M> {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        match Header::decode_raw(buf)? {
            // if the node is not a list, it must be empty or a digest
            PayloadView::String(payload) => match payload.len() {
                0 => Ok(Node::Null),
                32 => Ok(Node::Digest(B256::from_slice(payload))),
                _ => Err(alloy_rlp::Error::UnexpectedLength),
            },
            PayloadView::List(items) => match items.len() {
                // branch node: 17-item node [ v0 ... v15, value ]
                17 => {
                    let mut children = Children::default();
                    for (i, child_rlp) in items.iter().enumerate() {
                        if child_rlp != &[EMPTY_STRING_CODE] {
                            if i == 16 {
                                return Err(alloy_rlp::Error::Custom("branch node with value"));
                            } else {
                                children.insert(i as u8, Node::decode(&mut &child_rlp[..])?.into());
                            }
                        }
                    }
                    if children.len() < 2 {
                        return Err(alloy_rlp::Error::Custom("branch node without two children"));
                    }

                    Ok(Node::Branch(children, M::default()))
                }
                // leaf or extension node: 2-item node [ encodedPath, v ]
                // they are distinguished by a flag in the first nibble of the encodedPath
                2 => {
                    let [mut encode_path, mut v] = items.as_slice() else { unreachable!() };
                    let (path, is_leaf) = decode_path(&mut encode_path)?;
                    if is_leaf {
                        Ok(Node::Leaf(path, Bytes::decode(&mut v)?, M::default()))
                    } else {
                        let node = Node::decode(&mut v)?;
                        if !matches!(node, Node::Branch(..) | Node::Digest(..)) {
                            return Err(alloy_rlp::Error::Custom(
                                "extension node with invalid child",
                            ));
                        }
                        Ok(Node::Extension(path, node.into(), M::default()))
                    }
                }
                _ => Err(alloy_rlp::Error::Custom("unexpected list length")),
            },
        }
    }
}

/// An RLP-encoded node.
#[derive(Clone)]
pub(super) struct RlpNode(ArrayVec<u8, DIGEST_RLP_LENGTH>);

impl RlpNode {
    #[inline]
    fn from_rlp(rlp: impl AsRef<[u8]>) -> Self {
        let rlp = rlp.as_ref();
        if rlp.len() >= B256::len_bytes() {
            Self(alloy_rlp::encode_fixed_size(&keccak256(rlp)))
        } else {
            let mut arr = ArrayVec::new();
            // SAFETY: rlp.len() < 32 < DIGEST_RLP_LENGTH
            unsafe { arr.try_extend_from_slice(rlp).unwrap_unchecked() };
            Self(arr)
        }
    }

    #[inline]
    fn from_digest(digest: &B256) -> Self {
        Self(alloy_rlp::encode_fixed_size(digest))
    }

    #[inline]
    fn hash(&self) -> B256 {
        if self.0.len() == DIGEST_RLP_LENGTH {
            B256::from_slice(&self.0[1..])
        } else {
            keccak256(&self.0)
        }
    }
}

impl fmt::Debug for RlpNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl Encodable for RlpNode {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        out.put_slice(&self.0)
    }

    #[inline]
    fn length(&self) -> usize {
        self.0.len()
    }
}

/// Represents the way in which a node is referenced from within another node.
#[derive(Default)]
enum NodeRef<'a> {
    #[default]
    Empty,
    Digest(&'a B256),
    Cached(&'a RlpNode),
    Rlp(Vec<u8>),
}

impl NodeRef<'_> {
    #[inline]
    fn from_node<M: Memoization>(node: &Node<M>) -> NodeRef<'_> {
        match node {
            Node::Null => NodeRef::Empty,
            Node::Digest(digest) => NodeRef::Digest(digest),
            Node::Leaf(.., cache) | Node::Extension(.., cache) | Node::Branch(.., cache) => {
                cache.get().map_or_else(|| NodeRef::Rlp(node.rlp_encoded()), NodeRef::Cached)
            }
        }
    }

    #[inline]
    fn hash(&self) -> B256 {
        match self {
            NodeRef::Empty => EMPTY_ROOT_HASH,
            NodeRef::Digest(&digest) => digest,
            NodeRef::Cached(rlp_node) => rlp_node.hash(),
            NodeRef::Rlp(rlp) => keccak256(rlp),
        }
    }
}

impl Encodable for NodeRef<'_> {
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            NodeRef::Empty => out.put_u8(EMPTY_STRING_CODE),
            NodeRef::Digest(digest) => digest.encode(out),
            NodeRef::Cached(rlp_node) => rlp_node.encode(out),
            NodeRef::Rlp(rlp) => {
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
        match self {
            NodeRef::Empty => 1,
            NodeRef::Digest(_) => DIGEST_RLP_LENGTH,
            NodeRef::Cached(rlp_node) => rlp_node.length(),
            NodeRef::Rlp(rlp) => {
                if rlp.len() >= B256::len_bytes() {
                    DIGEST_RLP_LENGTH
                } else {
                    rlp.len()
                }
            }
        }
    }
}

#[inline]
fn encode_list_header(payload_length: usize) -> Vec<u8> {
    debug_assert!(payload_length > 1);
    let header = Header { list: true, payload_length };
    let mut out = Vec::with_capacity(header.length() + payload_length);
    header.encode(&mut out);
    out
}

#[inline]
fn decode_path(buf: &mut &[u8]) -> alloy_rlp::Result<(Nibbles, bool)> {
    let path = Nibbles::unpack(Header::decode_bytes(buf, false)?);
    if path.len() < 2 {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let (is_leaf, odd_nibbles) = match path[0] {
        0b0000 => (false, false),
        0b0001 => (false, true),
        0b0010 => (true, false),
        0b0011 => (true, true),
        _ => return Err(alloy_rlp::Error::Custom("node is not an extension or leaf")),
    };
    let prefix = if odd_nibbles { &path[1..] } else { &path[2..] };
    Ok((Nibbles::from_nibbles_unchecked(prefix), is_leaf))
}

fn encode_list<B, T>(values: &[B]) -> Vec<u8>
where
    B: std::borrow::Borrow<T>,
    T: ?Sized + Encodable,
{
    let mut payload_length = 0;
    for value in values {
        payload_length += value.borrow().length();
    }
    let mut out = encode_list_header(payload_length);
    for value in values {
        value.borrow().encode(&mut out);
    }
    out
}
