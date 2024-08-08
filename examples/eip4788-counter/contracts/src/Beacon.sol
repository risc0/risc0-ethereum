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

import {Steel} from "risc0/steel/Steel.sol";

/// @title Steel Beacon Chain library
library Beacon {
    /// @notice The address of the Beacon roots contract.
    /// @dev https://eips.ethereum.org/EIPS/eip-4788
    address internal constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice The Beacon block root could not be found as the next block has not been issued yet.
    error NoParentBeaconBlock();

    /// @notice Attempts to find the root of the Beacon block with the given timestamp.
    /// @dev Since the Beacon roots contract only returns the parent Beacon block’s root, we need to find the next
    ///      Beacon block instead. This is done by adding the block time of 12s until a value is returned.
    function blockRoot(uint256 timestamp) internal view returns (bytes32 root) {
        uint256 blockTimestamp = block.timestamp;
        while (true) {
            timestamp += 12;
            if (timestamp > blockTimestamp) revert NoParentBeaconBlock();

            (bool success, bytes memory result) = BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp));
            if (success) {
                return abi.decode(result, (bytes32));
            }
        }
    }

    /// @notice Validates if the provided Commitment matches the Beacon block root of the given timestamp.
    /// @param commitment The Commitment struct to validate.
    /// @return isValid True if the commitment's block hash matches the Beacon block root, false otherwise.
    function validateCommitment(Steel.Commitment memory commitment) internal view returns (bool) {
        // for Beacon Chain commitments the blockNumber corresponds to the timestamp and blockHash to the root
        bytes32 blockHash = Beacon.blockRoot(commitment.blockNumber);
        return commitment.blockHash == blockHash;
    }
}
