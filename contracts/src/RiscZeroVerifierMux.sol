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

import {Ownable} from "openzeppelin/contracts/access/Ownable.sol";

import {IRiscZeroVerifier, Receipt} from "./IRiscZeroVerifier.sol";

/// @notice Multiplexer for IRiscZeroVerifier, allowing multiple implementations to be callable from a single address.
// TODO(victor): Consider renaming "mux" to something else.
contract RiscZeroVerifierMux is IRiscZeroVerifier, Ownable {
    /// @notice Mapping from 4-byte proof identifiers to verifier contracts.
    /// Used to route receipts to verifiers that are able to determine the validity of the receipt.
    mapping(bytes4 => IRiscZeroVerifier) public verifiers;

    /// @notice Value of an entry that has never been set.
    IRiscZeroVerifier internal constant UNSET = IRiscZeroVerifier(address(0));
    /// @notice A "tombstone" value used to mark verifier entries that have been removed from the mapping.
    IRiscZeroVerifier internal constant TOMBSTONE = IRiscZeroVerifier(address(1));

    error IdentifierInUse(bytes4 identifier);
    error IdentifierRemoved(bytes4 identifier);
    error IdentifierUnknown(bytes4 identifier);

    constructor() Ownable(_msgSender()) {}

    /// @notice Adds a verifier to the mux, such that it can receive receipt verification calls.
    function addVerifier(bytes4 identifier, IRiscZeroVerifier verifier) external onlyOwner {
        if (verifiers[identifier] == TOMBSTONE) {
            revert IdentifierRemoved({identifier: identifier});
        }
        if (verifiers[identifier] != UNSET) {
            revert IdentifierInUse({identifier: identifier});
        }
        verifiers[identifier] = verifier;
    }

    /// @notice Removes an identifier from the mux, such that it can no receive verification calls.
    ///         Removing an identifier sets it to the tombstone value. It can never be set to any
    ///         other value, and can never be reused for a new verifier, in order to enfoce the
    ///         property that each identifier maps to at most one implementations across time.
    function removeVerifier(bytes4 identifier) external onlyOwner {
        // Simple check to reduce the chance of accidents.
        if (verifiers[identifier] == UNSET) {
            revert IdentifierUnknown({identifier: identifier});
        }
        verifiers[identifier] = TOMBSTONE;
    }

    /// @notice Get the associatied verifier, reverting if the identifier is unknown or removed.
    function getVerifier(bytes4 identifier) public view returns (IRiscZeroVerifier) {
        IRiscZeroVerifier verifier = verifiers[identifier];
        if (verifier == UNSET) {
            revert IdentifierUnknown({identifier: identifier});
        }
        if (verifier == TOMBSTONE) {
            revert IdentifierRemoved({identifier: identifier});
        }
        return verifier;
    }

    /// @notice Get the associatied verifier, reverting if the identifier is unknown or removed.
    function getVerifier(bytes calldata seal) public view returns (IRiscZeroVerifier) {
        // Use the first 4 bytes of the seal at the identifier to look up in the mapping.
        // TODO(victor): Is this bounds checked?
        return getVerifier(bytes4(seal[0:4]));
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 postStateDigest, bytes32 journalDigest)
        external
        view
        returns (bool)
    {
        return getVerifier(seal).verify(seal, imageId, postStateDigest, journalDigest);
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) external view returns (bool) {
        return getVerifier(receipt.seal).verifyIntegrity(receipt);
    }
}
