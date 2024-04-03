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

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.

/// @title Counter.
/// @notice Implements a counter that increments based on off-chain view call proofs submitted to this contract.
/// @dev The contract interacts with ERC-20 tokens, using view call proofs to verify that an account holds at least 1 token
/// before incrementing the counter. This contract leverages RISC0-zkVM for generating and verifying these proofs.
contract Counter {
    struct BlockCommitment {
        bytes32 blockHash;
        uint256 blockNumber;
    }
    /// @notice RISC Zero verifier contract address.

    IRiscZeroVerifier public immutable verifier;
    /// @notice Image ID of the only zkVM binary to accept verification from.
    bytes32 public constant imageId = ImageID.BALANCE_OF_ID;

    /// @notice Counter to track the number of successful verifications.
    uint256 public counter;

    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
        counter = 0;
    }

    /// @dev Increment the counter if the view call proof verifies that
    /// the specified account holds at least 1 token.
    ///
    /// The view call proof must be generated off-chain using RISC0-zkVM and submitted here.
    /// This function performs the proof verification process.
    function increment(bytes calldata journal, bytes32 postStateDigest, bytes calldata seal) public {
        // Construct the expected journal data. Verify will fail if journal does not match.
        BlockCommitment memory commitment = abi.decode(journal, (BlockCommitment));
        require(blockhash(commitment.blockNumber) == commitment.blockHash);
        require(verifier.verify(seal, imageId, postStateDigest, sha256(journal)));
        counter = counter + 1;
    }

    /// @notice Returns the value of the counter.
    function get() public view returns (uint256) {
        return counter;
    }
}
