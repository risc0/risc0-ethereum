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

interface ICounter {
    /// @notice Increments the counter, if the Steel proof verifies that the specified account holds at least 1 token.
    /// @dev The Steel proof must be generated off-chain using RISC0-zkVM and submitted here.
    function increment(bytes calldata journalData, bytes calldata seal) external;

    /// @notice Returns the value of the counter.
    function get() external view returns (uint256);

    /// @notice Returns the image ID used for verification.
    function imageID() external view returns (bytes32);
}
