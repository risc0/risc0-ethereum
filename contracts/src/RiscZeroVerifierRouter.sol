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

import {Ownable, Ownable2Step} from "openzeppelin/contracts/access/Ownable2Step.sol";

import {IRiscZeroVerifier, Receipt} from "./IRiscZeroVerifier.sol";

/// @notice Router for IRiscZeroVerifier, allowing multiple implementations to be accessible behind a single address.
contract RiscZeroVerifierRouter is IRiscZeroVerifier, Ownable2Step {
    /// @notice Mapping from 4-byte verifier selector to verifier contracts.
    ///         Used to route receipts to verifiers that are able to check the receipt.
    mapping(bytes4 => IRiscZeroVerifier) public verifiers;

    /// @notice Value of an entry that has never been set.
    IRiscZeroVerifier internal constant UNSET = IRiscZeroVerifier(address(0));
    /// @notice A "tombstone" value used to mark verifier entries that have been removed from the mapping.
    IRiscZeroVerifier internal constant TOMBSTONE = IRiscZeroVerifier(address(1));

    /// @notice Error raised when attempting to verify a receipt with a selector that is not
    ///         registered on this router. Generally, this indicates a version mismatch where the
    ///         prover generated a receipt with version of the zkVM that does not match any
    ///         registered version on this router contract.
    error SelectorUnknown(bytes4 selector);
    /// @notice Error raised when attempting to add a verifier for a selector that is already registered.
    error SelectorInUse(bytes4 selector);
    /// @notice Error raised when attempting to verify a receipt with a selector that has been
    ///         removed, or attempting to add a new verifier with a selector that was previously
    ///         registered and then removed.
    error SelectorRemoved(bytes4 selector);

    constructor(address admin) Ownable(admin) {}

    /// @notice Adds a verifier to the router, such that it can receive receipt verification calls.
    function addVerifier(bytes4 selector, IRiscZeroVerifier verifier) external onlyOwner {
        if (verifiers[selector] == TOMBSTONE) {
            revert SelectorRemoved({selector: selector});
        }
        if (verifiers[selector] != UNSET) {
            revert SelectorInUse({selector: selector});
        }
        verifiers[selector] = verifier;
    }

    /// @notice Removes verifier from the router, such that it can not receive verification calls.
    ///         Removing a selector sets it to the tombstone value. It can never be set to any
    ///         other value, and can never be reused for a new verifier, in order to enforce the
    ///         property that each selector maps to at most one implementation across time.
    function removeVerifier(bytes4 selector) external onlyOwner {
        // Simple check to reduce the chance of accidents.
        // NOTE: If there ever _is_ a reason to remove a selector that has never been set, the owner
        // can call addVerifier with the tombstone address.
        if (verifiers[selector] == UNSET) {
            revert SelectorUnknown({selector: selector});
        }
        verifiers[selector] = TOMBSTONE;
    }

    /// @notice Get the associatied verifier, reverting if the selector is unknown or removed.
    function getVerifier(bytes4 selector) public view returns (IRiscZeroVerifier) {
        IRiscZeroVerifier verifier = verifiers[selector];
        if (verifier == UNSET) {
            revert SelectorUnknown({selector: selector});
        }
        if (verifier == TOMBSTONE) {
            revert SelectorRemoved({selector: selector});
        }
        return verifier;
    }

    /// @notice Get the associatied verifier, reverting if the selector is unknown or removed.
    function getVerifier(bytes calldata seal) public view returns (IRiscZeroVerifier) {
        // Use the first 4 bytes of the seal at the selector to look up in the mapping.
        return getVerifier(bytes4(seal[0:4]));
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view {
        getVerifier(seal).verify(seal, imageId, journalDigest);
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) external view {
        getVerifier(receipt.seal).verifyIntegrity(receipt);
    }
}
