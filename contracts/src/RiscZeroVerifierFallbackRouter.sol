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

pragma solidity ^0.8.9;

import {IRiscZeroVerifier} from "./IRiscZeroVerifier.sol";
import {RiscZeroVerifierRouter} from "./RiscZeroVerifierRouter.sol";

/// @notice Router for IRiscZeroVerifier, allowing multiple implementations to be accessible behind a single address
///         and a fallback to the canonical router.
/// @dev Extends RiscZeroVerifierRouter to add fallback behavior.
contract RiscZeroVerifierFallbackRouter is RiscZeroVerifierRouter {
    /// @notice The canonical RISC Zero verifier router used as fallback.
    IRiscZeroVerifier public immutable fallbackRouter;

    constructor(address owner, IRiscZeroVerifier verifier) RiscZeroVerifierRouter(owner) {
        require(address(verifier) != address(0), "Fallback router address cannot be zero");
        fallbackRouter = verifier;
    }

    /// @notice Gets the canonical RISC Zero verifier router.
    function getFallbackRouter() external view returns (IRiscZeroVerifier) {
        return fallbackRouter;
    }

    /// @notice Adds a verifier to the router, such that it can receive receipt verification calls.
    function addVerifier(bytes4 selector, IRiscZeroVerifier verifier) external override onlyOwner {
        RiscZeroVerifierRouter router = RiscZeroVerifierRouter(address(fallbackRouter));
        // Ensure the selector is not removed from the fallback router.
        if (router.verifiers(selector) == TOMBSTONE) {
            revert SelectorRemoved({selector: selector});
        }
        // Ensure the selector is not already in use in the fallback router.
        if (router.verifiers(selector) != UNSET) {
            revert SelectorInUse({selector: selector});
        }
        // Ensure the selector is not removed from this router.
        if (verifiers[selector] == TOMBSTONE) {
            revert SelectorRemoved({selector: selector});
        }
        // Ensure the selector is not already in use in this router.
        if (verifiers[selector] != UNSET) {
            revert SelectorInUse({selector: selector});
        }
        // Ensure the verifier address is not zero.
        if (address(verifier) == address(0)) {
            revert VerifierAddressZero();
        }
        verifiers[selector] = verifier;
    }

    /// @notice Get the associated verifier, falling back to the canonical router if unset.
    /// @dev Overrides the base implementation to add fallback behavior.
    function getVerifier(bytes4 selector) public view override returns (IRiscZeroVerifier) {
        IRiscZeroVerifier verifier = verifiers[selector];
        // If the verifier is unset, fall back to the canonical router.
        if (verifier == UNSET) {
            return fallbackRouter;
        }
        if (verifier == TOMBSTONE) {
            revert SelectorRemoved({selector: selector});
        }
        return verifier;
    }
}
