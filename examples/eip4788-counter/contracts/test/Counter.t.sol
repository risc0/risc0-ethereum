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
import {Counter} from "../src/Counter.sol";
import {Steel, Beacon, Encoding} from "risc0/steel/Steel.sol";
import {ERC20} from "openzeppelin-contracts/token/ERC20/ERC20.sol";

contract ERC20FixedSupply is ERC20 {
    constructor(string memory name, string memory symbol, address owner) ERC20(name, symbol) {
        _mint(owner, 1000);
    }
}

contract CounterTest is Test {
    bytes4 constant MOCK_SELECTOR = bytes4(0);

    RiscZeroMockVerifier private verifier;
    ERC20 private token;
    Counter private counter;
    bytes32 private imageId;

    function setUp() public {
        // fork from the actual chain to get realestic Beacon block roots
        string memory RPC_URL = vm.envString("ETH_RPC_URL");
        vm.createSelectFork(RPC_URL);

        verifier = new RiscZeroMockVerifier(MOCK_SELECTOR);
        token = new ERC20FixedSupply("TOYKEN", "TOY", address(0x01));
        counter = new Counter(verifier, address(token));
        imageId = counter.imageId();
    }

    function testCounter() public {
        // get the root of the previous Beacon block
        uint240 beaconTimestamp = uint240(block.timestamp - 12);
        bytes32 beaconRoot = Beacon.blockRoot(beaconTimestamp);

        // mock the Journal
        Counter.Journal memory journal = Counter.Journal({
            commitment: Steel.Commitment(Encoding.encodeVersionedID(beaconTimestamp, 1), beaconRoot),
            tokenContract: address(token)
        });
        // create a mock proof
        RiscZeroReceipt memory receipt = verifier.mockProve(imageId, sha256(abi.encode(journal)));

        uint256 previous_count = counter.counter();

        counter.increment(abi.encode(journal), receipt.seal);

        // check that the counter was incremented
        assert(counter.counter() == previous_count + 1);
    }
}
