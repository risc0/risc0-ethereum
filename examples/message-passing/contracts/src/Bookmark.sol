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

import {IBookmark} from "./IBookmark.sol";
import {IL1Block} from "./IL1Block.sol";

contract Bookmark is IBookmark {
    /// @notice Address of the L1Block contract.
    IL1Block private immutable L1_BLOCK;

    mapping(uint64 blockNumber => bytes32 blockHash) internal blocks;

    constructor(IL1Block l1Block) {
        L1_BLOCK = l1Block;
    }

    function bookmarkL1Block() external returns (uint64) {
        uint64 blockNumber = L1_BLOCK.number();
        bytes32 blockHash = L1_BLOCK.hash();

        blocks[blockNumber] = blockHash;
        emit BookmarkedL1Block(blockNumber, blockHash);

        return blockNumber;
    }

    function getBookmark(uint64 blockNumber) external view returns (bytes32) {
        return blocks[blockNumber];
    }
}
