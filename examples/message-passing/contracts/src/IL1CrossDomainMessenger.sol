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

interface IL1CrossDomainMessenger {
    /// @notice Emitted whenever a message is sent to the other chain.
    /// @param target       Address of the recipient of the message.
    /// @param sender       Address of the sender of the message.
    /// @param data         Message to trigger the recipient address with.
    /// @param messageNonce Unique nonce attached to the message.
    event SentMessage(address indexed target, address sender, bytes data, uint256 messageNonce);

    /// @notice Returns whether the digest of the message has been committed to be relayed.
    function contains(bytes32 digest) external view returns (bool);

    /// @notice Sends a new message by commiting to its digest.
    function sendMessage(address target, bytes calldata data) external;

    /// @notice Retrieves the next message nonce.
    function messageNonce() external view returns (uint256);
}
