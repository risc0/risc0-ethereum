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
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {ReceiptClaim, ReceiptClaimLib} from "../src/IRiscZeroVerifier.sol";
import {Seal, RiscZeroSetVerifier} from "../src/RiscZeroSetVerifier.sol";

library TestUtils {
    /// Domain-separating tag value prepended to a digest before being hashed to form leaf node.
    ///
    /// Copied from RiscZeroSetVerifier.sol, as this value is not part of the public interface.
    bytes8 internal constant LEAF_TAG = bytes8("LEAF_TAG");

    using ReceiptClaimLib for ReceiptClaim;

    struct Proof {
        bytes32[] siblings;
    }

    // Build the Merkle Tree and return the root and the entire tree structure
    function computeMerkleTree(bytes32[] memory values) internal pure returns (bytes32 root, bytes32[][] memory tree) {
        require(values.length > 0, "Values list is empty, cannot compute Merkle root");

        // Calculate the height of the tree (number of levels)
        uint256 numLevels = log2Ceil(values.length) + 1;

        // Initialize the tree structure
        tree = new bytes32[][](numLevels);

        // Hash the values with the leaf tag to form the leaf nodes.
        tree[0] = new bytes32[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            tree[0][i] = hashLeaf(values[i]);
        }

        // Build the tree level by level
        uint256 currentLevelSize = values.length;
        for (uint256 level = 0; currentLevelSize > 1; level++) {
            uint256 nextLevelSize = (currentLevelSize + 1) / 2;
            tree[level + 1] = new bytes32[](nextLevelSize);

            for (uint256 i = 0; i < nextLevelSize; i++) {
                uint256 leftIndex = i * 2;
                uint256 rightIndex = leftIndex + 1;

                bytes32 leftHash = tree[level][leftIndex];
                if (rightIndex < currentLevelSize) {
                    bytes32 rightHash = tree[level][rightIndex];

                    tree[level + 1][i] = MerkleProofish._hashPair(leftHash, rightHash);
                } else {
                    // If the node has no right sibling, copy it up to the next level.
                    tree[level + 1][i] = leftHash;
                }
            }

            currentLevelSize = nextLevelSize;
        }

        root = tree[tree.length - 1][0];
    }

    function computeProofs(bytes32[][] memory tree) internal pure returns (Proof[] memory proofs) {
        uint256 numLeaves = tree[0].length;
        uint256 proofLength = tree.length - 1; // Maximum possible length of the proof
        proofs = new Proof[](numLeaves);

        // Generate proof for each leaf
        for (uint256 leafIndex = 0; leafIndex < numLeaves; leafIndex++) {
            bytes32[] memory tempSiblings = new bytes32[](proofLength);
            uint256 actualProofLength = 0;
            uint256 index = leafIndex;

            // Collect the siblings for the proof
            for (uint256 level = 0; level < tree.length - 1; level++) {
                uint256 siblingIndex = (index % 2 == 0) ? index + 1 : index - 1;

                if (siblingIndex < tree[level].length) {
                    tempSiblings[actualProofLength] = tree[level][siblingIndex];
                    actualProofLength++;
                }

                index /= 2;
            }

            // Adjust the length of the proof to exclude any unused slots
            proofs[leafIndex].siblings = new bytes32[](actualProofLength);
            for (uint256 i = 0; i < actualProofLength; i++) {
                proofs[leafIndex].siblings[i] = tempSiblings[i];
            }
        }
    }

    function hashLeaf(bytes32 value) internal pure returns (bytes32 leaf) {
        return keccak256(abi.encodePacked(LEAF_TAG, value));
    }

    function encodeSeal(RiscZeroSetVerifier setVerifier, TestUtils.Proof memory merkleProof, bytes memory rootSeal)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeWithSelector(setVerifier.SELECTOR(), Seal({path: merkleProof.siblings, rootSeal: rootSeal}));
    }

    function encodeSeal(RiscZeroSetVerifier setVerifier, TestUtils.Proof memory merkleProof)
        internal
        view
        returns (bytes memory)
    {
        bytes memory rootSeal;
        return encodeSeal(setVerifier, merkleProof, rootSeal);
    }

    function append(Proof memory proof, bytes32 newNode) internal pure returns (Proof memory) {
        bytes32[] memory newSiblings = new bytes32[](proof.siblings.length + 1);
        for (uint256 i = 0; i < proof.siblings.length; i++) {
            newSiblings[i] = proof.siblings[i];
        }
        newSiblings[proof.siblings.length] = newNode;
        proof.siblings = newSiblings;
        return proof;
    }

    function log2Ceil(uint256 x) private pure returns (uint256) {
        uint256 res = 0;
        uint256 value = x;
        while (value > 1) {
            value = (value + 1) / 2;
            res += 1;
        }
        return res;
    }
}

// Functions copied from OZ MerkleProof library to allow building the Merkle tree above.
library MerkleProofish {
    /**
     * @dev Sorts the pair (a, b) and hashes the result.
     */
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    /**
     * @dev Implementation of keccak256(abi.encode(a, b)) that doesn't allocate or expand memory.
     */
    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
