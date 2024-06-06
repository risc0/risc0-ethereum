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
import {Pausable} from "openzeppelin/contracts/utils/Pausable.sol";

import {IRiscZeroVerifier, Receipt} from "./IRiscZeroVerifier.sol";

/// @notice Wrapper for an IRiscZeroVerifier contract, providing emergency stop function.
contract RiscZeroVerifierEmergencyStop is IRiscZeroVerifier, Ownable2Step, Pausable {
    IRiscZeroVerifier public immutable verifier;

    /// @notice Error raised when calling estop with a receipt that cannot be verified as proof
    /// of an exploit on the verifier contract.
    error InvalidProofOfExploit();

    constructor(IRiscZeroVerifier _verifier, address guardian) Ownable(guardian) {
        verifier = _verifier;
    }

    /// @notice Initiate an emergency stop of the verifier contract.
    ///         Can only be used by the guardian address assigned as owner of this contract.
    ///
    ///         When stopped, all calls to the verify and verifyIntegrity functions will revert.
    ///         Once stopped, this contract can never be restarted.
    function estop() external onlyOwner {
        _pause();
    }

    /// @notice Initiate an emergency stop of the verifier contract, via the "circuit breaker".
    ///         This method can be called by anyone who can produce a verifying proof for a receipt
    ///         claim digest of all zeroes. The existence of such a proof demonstrates a critical
    ///         vulnerability in the proof system.
    ///
    ///         When stopped, all calls to the verify and verifyIntegrity functions will revert.
    ///         Once stopped, this contract can never be restarted.
    function estop(Receipt calldata receipt) external {
        if (receipt.claimDigest != bytes32(0)) {
            revert InvalidProofOfExploit();
        }
        // Check that the proof of exploit receipt really does verify.
        verifyIntegrity(receipt);
        _pause();
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view whenNotPaused {
        // Forward the call on to the wrapped contract.
        verifier.verify(seal, imageId, journalDigest);
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) public view whenNotPaused {
        // Forward the call on to the wrapped contract.
        verifier.verifyIntegrity(receipt);
    }
}
