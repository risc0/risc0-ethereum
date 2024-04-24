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

import {BytesLib} from "solidity-bytes-utils/BytesLib.sol";

import {
    ExitCode,
    IRiscZeroVerifier,
    Output,
    OutputLib,
    Receipt,
    ReceiptClaim,
    ReceiptClaimLib,
    SystemExitCode
} from "../IRiscZeroVerifier.sol";

/// @notice Mock verifier contract for RISC Zero receipts of execution.
contract RiscZeroMockVerifier is IRiscZeroVerifier {
    using ReceiptClaimLib for ReceiptClaim;
    using OutputLib for Output;
    using BytesLib for bytes;

    /// @notice A short key attached to the seal to select the correct verifier implementation.
    /// @dev A selector is not intended to be collision resistant, in that it is possible to find
    ///      two preimages that result in the same selector. This is acceptable since it's purpose
    ///      to a route a request among a set of trusted verifiers, and to make errors of sending a
    ///      receipt to a mismatching verifiers easier to debug. It is analogous to the ABI
    ///      function selectors.
    bytes4 public immutable SELECTOR;

    constructor(bytes32 salt) {
        SELECTOR = bytes4(
            keccak256(
                abi.encode(
                    // Identifier for the proof system.
                    "RISC_ZERO_MOCK",
                    // A salt provided to mock multiple, mutually incompatible verifiers.
                    salt
                )
            )
        );
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 postStateDigest, bytes32 journalDigest)
        public
        view
        returns (bool)
    {
        return _verifyIntegrity(seal, ReceiptClaimLib.from(imageId, postStateDigest, journalDigest).digest());
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) public view returns (bool) {
        return _verifyIntegrity(receipt.seal, receipt.claimDigest);
    }

    /// @notice internal implementation of verifyIntegrity, factored to avoid copying calldata bytes to memory.
    function _verifyIntegrity(bytes calldata seal, bytes32 claimDigest) internal view returns (bool) {
        // Require that the seal be exactly equal to the selector and claim digest.
        // Reject if the caller may have sent a real seal.
        return seal.equal(abi.encodePacked(SELECTOR, claimDigest));
    }

    /// @notice Construct a mock receipt for the given image ID and journal.
    function mockProve(bytes32 imageId, bytes32 postStateDigest, bytes32 journalDigest)
        public
        view
        returns (Receipt memory)
    {
        return mockProve(ReceiptClaimLib.from(imageId, postStateDigest, journalDigest).digest());
    }

    /// @notice Construct a mock receipt for the given claim digest.
    /// @dev You can calculate the claimDigest from a ReceiptClaim by using ReceiptClaimLib.
    function mockProve(bytes32 claimDigest) public view returns (Receipt memory) {
        return Receipt(abi.encodePacked(SELECTOR, claimDigest), claimDigest);
    }
}
