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

import "./IL2CrossDomainMessenger.sol";
import "./ICounter.sol";

contract Counter is ICounter {
    IL2CrossDomainMessenger private immutable L2_CROSS_DOMAIN_MESSENGER;
    address private immutable L1_SENDER;

    uint256 private count;

    constructor(IL2CrossDomainMessenger l2CrossDomainMessenger, address l1Sender) {
        L2_CROSS_DOMAIN_MESSENGER = l2CrossDomainMessenger;
        L1_SENDER = l1Sender;
        count = 0;
    }

    function increment() external {
        require(
            msg.sender == address(L2_CROSS_DOMAIN_MESSENGER),
            "Counter: Only L2CrossDomainMessenger can increment the counter"
        );
        require(L2_CROSS_DOMAIN_MESSENGER.xDomainMessageSender() == L1_SENDER, "Counter: Invalid L1 sender");

        count++;
    }

    function get() external view returns (uint256) {
        return count;
    }
}
