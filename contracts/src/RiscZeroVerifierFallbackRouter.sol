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

import {Ownable, Ownable2Step} from "openzeppelin/contracts/access/Ownable2Step.sol";

import {IRiscZeroVerifier, Receipt} from "./IRiscZeroVerifier.sol";
import {RiscZeroVerifierRouter} from "./RiscZeroVerifierRouter.sol";

/// @notice Router for IRiscZeroVerifier, allowing multiple implementations to be accessible behind a single address
///         and a fallback to the canonical router.
contract RiscZeroVerifierFallbackRouter is RiscZeroVerifierRouter {
    /// @notice The canonical RISC Zero verifier router used as fallback.
    IRiscZeroVerifier public FALLBACK_ROUTER;

    constructor(address owner, IRiscZeroVerifier fallbackRouter) RiscZeroVerifierRouter(owner) {
        FALLBACK_ROUTER = fallbackRouter;
    }

    /// @notice Sets the canonical RISC Zero verifier router.
    function setFallbackRouter(IRiscZeroVerifier verifier) external onlyOwner {
        if (address(verifier) == address(0)) {
            revert VerifierAddressZero();
        }
        FALLBACK_ROUTER = verifier;
    }

    /// @notice Gets the canonical RISC Zero verifier router.
    function getFallbackRouter() external view returns (IRiscZeroVerifier) {
        return FALLBACK_ROUTER;
    }

    /// @notice Get the associated verifier, falling back to the canonical router if unset.
    /// @dev Overrides the base implementation to add fallback behavior.
    function getVerifier(bytes4 selector) public view override returns (IRiscZeroVerifier) {
        IRiscZeroVerifier verifier = verifiers[selector];
        // If the verifier is unset, fall back to the canonical router.
        if (verifier == UNSET) {
            // If no fallback router is set, revert.
            if (address(FALLBACK_ROUTER) == address(0)) {
                revert SelectorUnknown({selector: selector});
            }
            return FALLBACK_ROUTER;
        }
        if (verifier == TOMBSTONE) {
            revert SelectorRemoved({selector: selector});
        }
        return verifier;
    }
}
