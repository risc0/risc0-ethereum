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
import {Pausable} from "openzeppelin/contracts/utils/Pausable.sol";

import {IRiscZeroVerifier, Receipt} from "./IRiscZeroVerifier.sol";

/// @notice Wrapper for an IRiscZeroVerifier contracts with emergency stop function.
contract RiscZeroVerifierEmergencyStop is IRiscZeroVerifier, Ownable, Pausable {
    IRiscZeroVerifier immutable verifier;

    constructor(IRiscZeroVerifier _verifier) Ownable(_msgSender()) {
        verifier = _verifier;
    }

    /// @notice Initiate an emergency stop of the wrapped verifier contract.
    ///         This method can only be used by guardian address assigned as owner of this contract.
    ///         When stopped, all calls to the verify and verifyIntegrity functions will revert.
    ///         Once stopped, this contract can never be restarted.
    function estop() external onlyOwner {
        _pause();
    }

    /// @notice Initiate an emergency stop of the wrapped verifier contract.
    ///         This method can be called by anyone who can produce a verifying proof for a receipt
    ///         claim digest of all zeroes. The existence of such a proof demonstrates a critical
    ///         vulnerability in the proof system.
    ///         When stopped, all calls to the verify and verifyIntegrity functions will revert.
    ///         Once stopped, this contract can never be restarted.
    function estop(Receipt calldata receipt) external {
        require(receipt.claimDigest == bytes32(0), "receipt claim digest is non-zero");
        require(verifyIntegrity(receipt), "receipt verification failed");
        _pause();
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 postStateDigest, bytes32 journalDigest)
        external
        view
        whenNotPaused
        returns (bool)
    {
        // Forward the call on to the wrapped contract.
        return verifier.verify(seal, imageId, postStateDigest, journalDigest);
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) public view whenNotPaused returns (bool) {
        // Forward the call on to the wrapped contract.
        return verifier.verifyIntegrity(receipt);
    }
}