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

import {Message, Digest} from "./Structs.sol";
import {IL1CrossDomainMessenger} from "./IL1CrossDomainMessenger.sol";

contract L1CrossDomainMessenger is IL1CrossDomainMessenger {
    using Digest for Message;

    mapping(bytes32 => bool) private messages;
    uint256 private msgNonce;

    constructor() {
        msgNonce = 0;
    }

    function contains(bytes32 digest) external view returns (bool) {
        return messages[digest];
    }

    function sendMessage(address target, bytes calldata data) external {
        Message memory message = Message(target, msg.sender, data, messageNonce());
        messages[message.digest()] = true;

        emit SentMessage(message.target, message.sender, message.data, message.nonce);

        unchecked {
            ++msgNonce;
        }
    }

    function messageNonce() public view returns (uint256) {
        return msgNonce;
    }
}
