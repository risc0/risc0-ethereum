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
    event VerifiedRoot(bytes32 indexed root, bytes seal);

    /// Publishes a new root of a proof aggregation.
    function submitMerkleRoot(bytes32 root, bytes calldata seal) external;

    /// Returns whether `root` has been submitted.
    function containsRoot(bytes32 root) external view returns (bool);

    /// Returns the set builder imageId and its url.
    function imageInfo() external view returns (bytes32, string memory);
}
