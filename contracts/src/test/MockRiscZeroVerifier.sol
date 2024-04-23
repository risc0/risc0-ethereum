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
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    using BytesLib for bytes;

    /// @notice Identifier for this verifier
    // TODO(victor): Fill in the description here.
    bytes4 public immutable IDENTIFIER;

    constructor(bytes32 salt) {
        IDENTIFIER = bytes4(
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
    function verify(
        bytes calldata seal,
        bytes32,
        /*imageId*/
        bytes32, /*postStateDigest*/
        bytes32 /*journalDigest*/
    ) public view returns (bool) {
        // Require that the seal be exactly equal to the identifier.
        // Reject if the caller may have sent a real seal.
        return seal.equal(abi.encodePacked(IDENTIFIER));
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) public view returns (bool) {
        // Require that the seal be exactly equal to the identifier.
        // Reject if the caller may have sent a real seal.
        return receipt.seal.equal(abi.encodePacked(IDENTIFIER));
    }
}