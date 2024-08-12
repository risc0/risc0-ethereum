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

import {Steel} from "risc0/steel/Steel.sol";

/// @notice A Message to be relayed.
struct Message {
    address target;
    address sender;
    bytes data;
    uint256 nonce;
}

/// @notice The Journal returned by the guest.
struct Journal {
    /// @notice The actual Steel commitment.
    Steel.Commitment commitment;
    /// @notice Address of the L1 Messenger used to verify that the message was sent.
    address l1CrossDomainMessenger;
    /// @notice The actual message to be relayed.
    Message message;
    /// @notice Precomputed digest of the message.
    bytes32 messageDigest;
}

library Digest {
    bytes32 internal constant MESSAGE_TYPEHASH =
        keccak256("Message(address target,address sender,bytes data,uint256 nonce)");

    /// @notice Returns the `hashStruct` of the message as defined in EIP-712.
    function digest(Message memory message) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(MESSAGE_TYPEHASH, message.target, message.sender, keccak256(message.data), message.nonce)
        );
    }
}
