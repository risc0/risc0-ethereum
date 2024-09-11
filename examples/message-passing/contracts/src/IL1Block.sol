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

/// @notice The L1Block predeploy gives users access to information about the last known L1 block.
interface IL1Block {
    /// @notice The latest L1 block number known by the L2 system.
    function number() external view returns (uint64);

    /// @notice The latest L1 blockhash.
    function hash() external view returns (bytes32);
}
