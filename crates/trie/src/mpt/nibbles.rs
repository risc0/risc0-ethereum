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

//! A zero-cost abstraction for handling nibbles (4-bit values) as byte slices.
//!
//! This module provides `NibbleSlice`, a wrapper around `&[u8]` that guarantees
//! each byte represents a valid nibble (0-15). It offers efficient operations
//! for working with nibble data without runtime overhead.

use alloy_primitives::hex;
use alloy_trie::Nibbles;
use std::{fmt, ops::Deref};

/// A slice of bytes representing nibbles.
#[derive(Clone, Copy)]
pub(super) struct NibbleSlice<'a>(&'a [u8]);

impl Deref for NibbleSlice<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl fmt::Debug for NibbleSlice<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nibbles(0x{})", hex::encode(self.as_slice()))
    }
}

impl<'a> From<&'a Nibbles> for NibbleSlice<'a> {
    /// Creates a `NibbleSlice` from a `Nibbles` reference.
    #[inline]
    fn from(nibbles: &'a Nibbles) -> Self {
        Self(nibbles.as_slice())
    }
}

impl From<NibbleSlice<'_>> for Nibbles {
    /// Converts a `NibbleSlice` back into a `Nibbles`.
    #[inline]
    fn from(slice: NibbleSlice<'_>) -> Self {
        Nibbles::from_nibbles_unchecked(slice.0)
    }
}

#[allow(dead_code)]
impl<'a> NibbleSlice<'a> {
    #[inline]
    pub(super) const fn as_slice(&self) -> &'a [u8] {
        self.0
    }

    #[inline]
    pub(super) const fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub(super) const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub(super) fn join(&self, other: impl Into<Self>) -> Nibbles {
        let other = other.into();
        let mut nibbles = Nibbles::with_capacity(self.len() + other.len());
        nibbles.extend_from_slice_unchecked(self.as_slice());
        nibbles.extend_from_slice_unchecked(other.as_slice());
        nibbles
    }

    #[inline]
    pub(super) fn split_first(&self) -> Option<(u8, Self)> {
        self.0.split_first().map(|(nib, tail)| (*nib, Self(tail)))
    }

    #[inline]
    pub(super) fn strip_prefix(&self, prefix: &[u8]) -> Option<Self> {
        self.0.strip_prefix(prefix).map(Self)
    }

    #[inline]
    pub(super) fn strip_suffix(&self, suffix: &[u8]) -> Option<Self> {
        self.0.strip_suffix(suffix).map(Self)
    }

    /// Splits `self` and `other` at the first nibble that differs.
    #[inline]
    pub(super) fn split_common_prefix(&self, other: impl Into<Self>) -> (Self, Self, Self) {
        let (a, b) = (self.0, other.into().0);
        let mid = a.iter().zip(b).take_while(|&(x, y)| x == y).count();
        // SAFETY: mid is the length of the common prefix: mid <= a.len() ∧ mid <= b.len()
        let (common, a_tail) = unsafe { a.split_at_unchecked(mid) };
        (Self(common), Self(a_tail), Self(unsafe { b.split_at_unchecked(mid).1 }))
    }
}
