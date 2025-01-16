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
    memoize::Memoization,
    node::{Child, Node},
};
use std::slice::Iter;

/// Implements a helper wrapper for the children of a Branch node.
///
/// This wrapper offers various convenience features and assures that there is never a Null child.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent),
    serde(bound(serialize = "Node<M>: serde::Serialize")),
    serde(bound(deserialize = "Node<M>: serde::Deserialize<'de>"))
)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    rkyv(bytecheck(bounds(__C: rkyv::validation::ArchiveContext, __C::Error: rkyv::rancor::Source))),
    rkyv(serialize_bounds(__S: rkyv::ser::Writer + rkyv::ser::Allocator, __S::Error: rkyv::rancor::Source)),
    rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source, M: Default))
)]
pub(super) struct Children<M>(
    #[cfg_attr(feature = "rkyv", rkyv(omit_bounds))] [Option<Box<Node<M>>>; 16],
);

impl<M> Default for Children<M> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<M> PartialEq for Children<M> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<M> Eq for Children<M> where Node<M>: Eq {}

/// A view into a single entry in a children map, which may either be vacant or occupied.
///
/// This `enum` is constructed from the [`Children::entry`] method.
pub(super) enum Entry<'a, M> {
    Vacant(VacantEntry<'a, M>),
    Occupied(OccupiedEntry<'a, M>),
}

/// A view into a vacant entry in a children map.
/// It is part of the [`Entry`] enum.
pub(super) struct VacantEntry<'a, M> {
    child: &'a mut Option<Child<M>>,
}

/// A view into an occupied entry in a children map.
/// It is part of the [`Entry`] enum.
pub(super) struct OccupiedEntry<'a, M> {
    child: &'a mut Option<Child<M>>,
}

impl<M> Drop for OccupiedEntry<'_, M> {
    fn drop(&mut self) {
        if matches!(self.get(), Node::Null) {
            *self.child = None;
        }
    }
}

impl<'a, M> Entry<'a, M> {
    #[inline]
    fn new(child: &'a mut Option<Child<M>>) -> Self {
        match child {
            None => Entry::Vacant(VacantEntry { child }),
            Some(_) => Entry::Occupied(OccupiedEntry { child }),
        }
    }
}

impl<M> VacantEntry<'_, M> {
    /// Sets the child of the entry with the `VacantEntry`'s index, and returns a mutable reference
    /// to it.
    #[inline]
    pub(super) fn insert(self, child: Child<M>) {
        assert!(!matches!(child.as_ref(), Node::Null));
        *self.child = Some(child)
    }
}

impl<M> OccupiedEntry<'_, M> {
    /// Gets a reference to the child node in the entry.
    #[inline]
    pub(super) fn get(&self) -> &Node<M> {
        // SAFETY: an OccupiedEntry is only created for a child that is not `None`
        unsafe { self.child.as_deref().unwrap_unchecked() }
    }

    /// Gets a mutable reference to the child node in the entry.
    #[inline]
    pub(super) fn get_mut(&mut self) -> &mut Node<M> {
        // SAFETY: an OccupiedEntry is only created for a child that is not `None`
        unsafe { self.child.as_deref_mut().unwrap_unchecked() }
    }
}

#[allow(dead_code)]
impl<M> Children<M> {
    #[inline]
    pub(super) fn get(&self, idx: u8) -> Option<&Node<M>> {
        self.0[idx as usize].as_deref()
    }

    #[inline]
    pub(super) unsafe fn get_unchecked(&self, idx: u8) -> Option<&Node<M>> {
        self.0.get_unchecked(idx as usize).as_deref()
    }

    #[inline]
    pub(super) fn entry(&mut self, idx: u8) -> Entry<'_, M> {
        Entry::new(&mut self.0[idx as usize])
    }

    #[inline]
    pub(super) fn insert(&mut self, idx: u8, child: Child<M>) {
        assert!(!matches!(child.as_ref(), Node::Null));
        self.0[idx as usize] = Some(child);
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.0.iter().flatten().count()
    }

    pub(super) fn take_single_child(&mut self) -> Option<(u8, Child<M>)> {
        let mut child_idx = None;
        for (i, child) in self.0.iter().enumerate() {
            if child.is_some() {
                if child_idx.is_some() {
                    return None; // more than one child found
                }
                child_idx = Some(i);
            }
        }
        // SAFETY: if `child_idx` is only set when the corresponding child is `Some`
        child_idx.map(|i| (i as u8, unsafe { self.0[i].take().unwrap_unchecked() }))
    }

    #[inline]
    pub(super) fn iter(&self) -> Iter<'_, Option<Child<M>>> {
        self.0.iter()
    }

    #[inline]
    pub(super) fn into_iter(self) -> impl Iterator<Item = Option<Child<M>>> {
        self.0.into_iter()
    }

    #[inline]
    pub(super) fn entries(&mut self) -> impl Iterator<Item = Entry<'_, M>> {
        self.0.iter_mut().map(Entry::new)
    }
}

impl<M: Memoization> Children<M> {
    #[inline]
    pub(super) fn memoize(&mut self) {
        self.0.iter_mut().flatten().for_each(|child| child.memoize())
    }
}

impl<M, C: Into<Child<M>>, const N: usize> From<[(u8, C); N]> for Children<M> {
    fn from(arr: [(u8, C); N]) -> Self {
        let mut children = Children::default();
        for (idx, child) in arr {
            children.insert(idx, child.into());
        }
        children
    }
}
