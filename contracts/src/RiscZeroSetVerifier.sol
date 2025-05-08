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

import {MerkleProof} from "openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IRiscZeroVerifier, Receipt, ReceiptClaim, ReceiptClaimLib, VerificationFailed} from "./IRiscZeroVerifier.sol";
import {IRiscZeroSetVerifier, Seal} from "./IRiscZeroSetVerifier.sol";

/// @notice Error raised when this verifier receives a receipt with a selector that does not match
///         its own. The selector value is calculated from the verifier parameters, and so this
///         usually indicates a mismatch between the version of the prover and this verifier.
error SelectorMismatch(bytes4 received, bytes4 expected);

library RiscZeroSetVerifierLib {
    function selector(bytes32 imageId) internal pure returns (bytes4) {
        return bytes4(
            sha256(
                abi.encodePacked(
                    // tag
                    sha256("risc0.SetInclusionReceiptVerifierParameters"),
                    // down
                    imageId,
                    // down length
                    uint16(1) << 8
                )
            )
        );
    }
}

/// @notice RiscZeroSetVerifier verifier contract for RISC Zero receipts of execution.
contract RiscZeroSetVerifier is IRiscZeroSetVerifier {
    using ReceiptClaimLib for ReceiptClaim;

    /// Semantic version of the RISC Zero Set Verifier.
    string public constant VERSION = "0.7.0";

    /// Domain-separating tag value prepended to a digest before being hashed to form leaf node.
    ///
    /// NOTE: It is explicitly not 32 bytes to avoid any chance of collision with a node value.
    bytes8 internal constant LEAF_TAG = bytes8("LEAF_TAG");

    IRiscZeroVerifier public immutable VERIFIER;

    /// @notice A short key attached to the seal to select the correct verifier implementation.
    /// @dev The selector is taken from the hash of the verifier parameters including the set builder
    ///      guest image ID. If two receipts have different selectors (i.e. different verifier
    ///      parameters), then it can generally be assumed that they need distinct verifier
    ///      implementations. This is used as part of the RISC Zero versioning mechanism.
    ///
    ///      A selector is not intended to be collision resistant, in that it is possible to find
    ///      two preimages that result in the same selector. This is acceptable since it's purpose
    ///      to a route a request among a set of trusted verifiers, and to make errors of sending a
    ///      receipt to a mismatching verifiers easier to debug. It is analogous to the ABI
    ///      function selectors.
    bytes4 public immutable SELECTOR;

    bytes32 private immutable IMAGE_ID;
    string private imageUrl;

    mapping(bytes32 => bool) private merkleRoots;

    constructor(IRiscZeroVerifier verifier, bytes32 imageId, string memory _imageUrl) {
        VERIFIER = verifier;
        IMAGE_ID = imageId;
        imageUrl = _imageUrl;

        SELECTOR = RiscZeroSetVerifierLib.selector(imageId);
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) public view {
        _verifyIntegrity(seal, ReceiptClaimLib.ok(imageId, journalDigest).digest());
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) public view {
        _verifyIntegrity(receipt.seal, receipt.claimDigest);
    }

    /// @notice internal implementation of verifyIntegrity, factored to avoid copying calldata bytes to memory.
    function _verifyIntegrity(bytes calldata seal, bytes32 claimDigest) internal view {
        Seal memory setVerifierSeal;

        // Check that the seal has a matching selector. Mismatch generally  indicates that the
        // prover and this verifier are using different parameters, and so the verification
        // will not succeed.
        if (SELECTOR != bytes4(seal[:4])) {
            revert SelectorMismatch({received: bytes4(seal[:4]), expected: SELECTOR});
        }

        // Check if the seal is not empty and decode it, otherwise use an empty array
        // TODO(victor): Can we verify the Merkle inclusion without abi decoding into memory?
        if (seal.length > 4) {
            setVerifierSeal = abi.decode(seal[4:], (Seal));
        }

        // Hash the claim digest, prepending a leaf tag as a domain separator.
        bytes32 leaf = keccak256(abi.encodePacked(LEAF_TAG, claimDigest));

        // Compute the root and verify it against the stored Merkle roots if a
        // root seal was not provided, or validate the root seal.
        // NOTE: If an invalid root seal was provided, the verify will fail
        // even if the root was already verified earlier and stored in state.
        bytes32 root = MerkleProof.processProof(setVerifierSeal.path, leaf);
        if (setVerifierSeal.rootSeal.length > 0) {
            VERIFIER.verify(setVerifierSeal.rootSeal, IMAGE_ID, sha256(_encodeJournal(root)));
        } else if (!merkleRoots[root]) {
            revert VerificationFailed();
        }
    }

    function _encodeJournal(bytes32 root) internal view returns (bytes memory) {
        // The journal is the encoding of the guest state for a finalized Merkle mountain range.
        // See GuestState in the risc0-aggregation crate for more information.
        return abi.encodePacked(IMAGE_ID, uint256(1 << 255), root);
    }

    function submitMerkleRoot(bytes32 root, bytes calldata seal) external {
        VERIFIER.verify(seal, IMAGE_ID, sha256(_encodeJournal(root)));
        merkleRoots[root] = true;

        emit VerifiedRoot(root, seal);
    }

    function containsRoot(bytes32 root) external view returns (bool) {
        return merkleRoots[root];
    }

    function imageInfo() external view returns (bytes32, string memory) {
        return (IMAGE_ID, imageUrl);
    }
}
