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
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

/// @notice Interface to bookmark L1 blocks.
interface IBookmark {
    /// @notice A new L1 block has been bookmarked.
    event BookmarkedL1Block(uint64 number, bytes32 hash);

    /// @notice Bookmarks the current L1 block.
    function bookmarkL1Block() external returns (uint64);

    /// @notice Returns the bookmarked hash of the block with the given number.
    function getBookmark(uint64 blockNumber) external view returns (bytes32);
}
