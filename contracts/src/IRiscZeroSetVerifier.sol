// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";

/// Seal of the SetInclusionReceipt.
struct Seal {
    /// Merkle path to the leaf.
    bytes32[] path;
    /// Root seal.
    bytes rootSeal;
}

interface IRiscZeroSetVerifier is IRiscZeroVerifier {
    error VerificationFailed();

    /// A new root has been added to the set.
    event VerifiedRoot(bytes32 root);

    /// Publishes a new root of a proof aggregation.
    function submitMerkleRoot(bytes32 root, bytes calldata seal) external;

    /// Returns whether `root` has been submitted.
    function containsRoot(bytes32 root) external view returns (bool);

    /// Returns the set builder imageId and its url.
    function imageInfo() external view returns (bytes32, string memory);
}
