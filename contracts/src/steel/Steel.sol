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

pragma solidity ^0.8.9;

/// @title Steel Library
/// @notice This library provides a collection of utilities to work with Steel commitments in Solidity.
library Steel {
    /// @notice Represents a commitment to a specific block in the blockchain.
    /// @dev The `id` combines the version and the actual identifier of the claim, such as the block number.
    /// @dev The `digest` represents the data being committed to, e.g. the hash of the execution block.
    /// @dev The `configID` is the cryptographic digest of the network configuration.
    struct Commitment {
        uint256 id;
        bytes32 digest;
        bytes32 configID;
    }

    /// @notice The version of the Commitment is incorrect.
    error InvalidCommitmentVersion();

    /// @notice The Commitment is too old and can no longer be validated.
    error CommitmentTooOld();

    /// @notice Validates if the provided Commitment matches the block hash of the given block number.
    /// @param commitment The Commitment struct to validate.
    /// @return True if the commitment's block hash matches the block hash of the block number, false otherwise.
    function validateCommitment(Commitment memory commitment) internal view returns (bool) {
        (uint240 claimID, uint16 version) = Encoding.decodeVersionedID(commitment.id);
        if (version == 0) {
            return validateBlockCommitment(claimID, commitment.digest);
        } else if (version == 1) {
            return validateBeaconCommitment(claimID, commitment.digest);
        } else {
            revert InvalidCommitmentVersion();
        }
    }

    /// @notice Validates if the provided block commitment matches the block hash of the given block number.
    /// @param blockNumber The block number to compare against.
    /// @param blockHash The block hash to validate.
    /// @return True if the block's block hash matches the block hash, false otherwise.
    function validateBlockCommitment(uint256 blockNumber, bytes32 blockHash) internal view returns (bool) {
        if (block.number - blockNumber > 256) {
            revert CommitmentTooOld();
        }
        return blockHash == blockhash(blockNumber);
    }

    /// @notice Validates if the provided beacon commitment matches the block root of the given timestamp.
    /// @param timestamp The timestamp to compare against.
    /// @param blockRoot The block root to validate.
    /// @return True if the block's block root matches the block root, false otherwise.
    function validateBeaconCommitment(uint256 timestamp, bytes32 blockRoot) internal view returns (bool) {
        if (block.timestamp - timestamp > 12 * 8191) {
            revert CommitmentTooOld();
        }
        return blockRoot == Beacon.parentBlockRoot(timestamp);
    }
}

/// @title Beacon Library
library Beacon {
    /// @notice The address of the Beacon roots contract.
    /// @dev https://eips.ethereum.org/EIPS/eip-4788
    address internal constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice Find the root of the Beacon block corresponding to the parent of the execution block with the given timestamp.
    /// @return root Returns the corresponding Beacon block root or null, if no such block exists.
    function parentBlockRoot(uint256 timestamp) internal view returns (bytes32 root) {
        (bool success, bytes memory result) = BEACON_ROOTS_ADDRESS.staticcall(abi.encode(timestamp));
        if (success) {
            return abi.decode(result, (bytes32));
        }
    }
}

/// @title Encoding Library
library Encoding {
    /// @notice Encodes a version and ID into a single uint256 value.
    /// @param id The base ID to be encoded, limited by 240 bits (or the maximum value of a uint240).
    /// @param version The version number to be encoded, limited by 16 bits (or the maximum value of a uint16).
    /// @return Returns a single uint256 value that contains both the `id` and the `version` encoded into it.
    function encodeVersionedID(uint240 id, uint16 version) internal pure returns (uint256) {
        uint256 encoded;
        assembly {
            encoded := or(shl(240, version), id)
        }
        return encoded;
    }

    /// @notice Decodes a version and ID from a single uint256 value.
    /// @param id The single uint256 value to be decoded.
    /// @return Returns two values: a uint240 for the original base ID and a uint16 for the version number encoded into it.
    function decodeVersionedID(uint256 id) internal pure returns (uint240, uint16) {
        uint240 decoded;
        uint16 version;
        assembly {
            decoded := and(id, 0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
            version := shr(240, id)
        }
        return (decoded, version);
    }
}
