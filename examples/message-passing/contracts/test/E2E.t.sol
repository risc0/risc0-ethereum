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

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {Receipt as RiscZeroReceipt} from "risc0/IRiscZeroVerifier.sol";
import {RiscZeroMockVerifier} from "risc0/test/RiscZeroMockVerifier.sol";
import {Journal, Message, Digest} from "../src/Structs.sol";
import {IL1CrossDomainMessenger} from "../src/IL1CrossDomainMessenger.sol";
import {L1CrossDomainMessenger} from "../src/L1CrossDomainMessenger.sol";
import {IL1Block} from "../src/IL1Block.sol";
import {Journal, L2CrossDomainMessenger} from "../src/L2CrossDomainMessenger.sol";
import {L1BlockMock} from "./L1BlockMock.sol";
import {Counter} from "../src/Counter.sol";
import {Steel} from "risc0/steel/Steel.sol";

contract E2ETest is Test {
    using Digest for Message;
    using Digest for Journal;

    RiscZeroMockVerifier private verifier;
    L1CrossDomainMessenger private l1CrossDomainMessenger;
    L2CrossDomainMessenger private l2CrossDomainMessenger;
    IL1Block private l1Block;
    Counter private counter;
    address private sender;

    bytes32 internal CROSS_DOMAIN_MESSENGER_IMAGE_ID = bytes32(uint256(0x03));

    bytes4 MOCK_SELECTOR = bytes4(0);

    function setUp() public {
        sender = address(1);
        vm.startPrank(sender);

        l1CrossDomainMessenger = new L1CrossDomainMessenger();
        verifier = new RiscZeroMockVerifier(MOCK_SELECTOR);
        l1Block = new L1BlockMock();
        l2CrossDomainMessenger = new L2CrossDomainMessenger(
            verifier, CROSS_DOMAIN_MESSENGER_IMAGE_ID, address(l1CrossDomainMessenger), l1Block
        );
        counter = new Counter(l2CrossDomainMessenger, address(sender));
    }

    function testCounterIncrement() public {
        // pass Counter::increment() message
        address target = address(counter);
        bytes memory data = abi.encodeCall(Counter.increment, ());

        uint256 previous_count = counter.get();

        testCrossDomainMessenger(target, data);

        // check that the counter was incremented
        assert(counter.get() == previous_count + 1);
    }

    function testSHA256() public {
        // sha256 hash
        address target = address(0x02);
        bytes memory data = unicode"こんにちは世界!";

        testCrossDomainMessenger(target, data);
    }

    function testCrossDomainMessenger(address target, bytes memory data) internal {
        uint256 nonce = l1CrossDomainMessenger.messageNonce();

        // send a message on L1
        vm.expectEmit(true, true, false, true);
        emit IL1CrossDomainMessenger.SentMessage(target, sender, data, nonce);
        l1CrossDomainMessenger.sendMessage(target, data);

        // bookmark the next block
        vm.roll(1);
        uint256 blockNumber = l2CrossDomainMessenger.bookmarkL1Block();
        bytes32 blockHash = l1Block.hash();

        // mock the Journal
        Message memory message = Message(target, sender, data, nonce);
        Journal memory journal = Journal({
            commitment: Steel.Commitment(blockNumber, blockHash),
            l1CrossDomainMessenger: address(l1CrossDomainMessenger),
            message: message,
            messageDigest: message.digest()
        });
        // create a mock proof
        RiscZeroReceipt memory receipt =
            verifier.mockProve(CROSS_DOMAIN_MESSENGER_IMAGE_ID, sha256(abi.encode(journal)));

        // relay the message on L2
        l2CrossDomainMessenger.relayMessage(abi.encode(journal), receipt.seal);
    }
}
