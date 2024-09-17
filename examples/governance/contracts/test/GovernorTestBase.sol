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

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {BaselineGovernor} from "../src/BaselineGovernor.sol";
import {RiscZeroGovernor} from "../src/RiscZeroGovernor.sol";
import {VoteToken} from "../src/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {ImageID} from "../src/ImageID.sol";
import {RiscZeroMockVerifier, Receipt as VerifierReceipt} from "risc0/test/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract GovernorTestBase is Test {
    BaselineGovernor public baselineGovernor;
    RiscZeroGovernor public riscZeroGovernor;
    VoteToken public voteToken;
    RiscZeroMockVerifier public mockVerifier;

    address public alice;
    address public bob;
    address public charlie;
    address public voterAddress;
    uint256 public voterPk;

    bytes32 public constant IMAGE_ID = ImageID.FINALIZE_VOTES_ID;
    bytes4 public constant MOCK_SELECTOR = bytes4(uint32(1337));

    event VoteCast(address indexed voter, uint256 proposalId, uint8 support, uint256 weight, string reason);

    function setUp() public virtual {
        voteToken = new VoteToken();
        mockVerifier = new RiscZeroMockVerifier(MOCK_SELECTOR);
        baselineGovernor = new BaselineGovernor(voteToken);
        riscZeroGovernor = new RiscZeroGovernor(voteToken, IMAGE_ID, mockVerifier);

        alice = vm.addr(1);
        bob = vm.addr(2);
        charlie = vm.addr(3);

        voteToken.mint(alice, 100);
        voteToken.mint(bob, 50);
        voteToken.mint(charlie, 30);

        vm.prank(alice);
        voteToken.delegate(alice);
        vm.prank(bob);
        voteToken.delegate(bob);
        vm.prank(charlie);
        voteToken.delegate(charlie);

        (voterAddress, voterPk) = makeAddrAndKey("voter");
    }

    function getSignature(uint8 support, uint256 proposalId, address signer, uint256 privateKey)
        internal
        returns (bytes memory signature)
    {
        bytes32 digest = baselineGovernor.voteHash(proposalId, support, signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    // this function replicates the behavior of _commitVote in RiscZeroGovernorCounting.sol
    function hashBallots(uint8 aliceSupport, uint8 bobSupport, uint256 proposalId)
        internal
        view
        returns (bytes32, bytes memory)
    {
        bytes memory encodeAliceVote = abi.encodePacked(uint16(0), aliceSupport, uint8(0), alice);
        bytes memory encodeBobVote = abi.encodePacked(uint16(0), bobSupport, uint8(0), bob);
        bytes memory encodedBallots = bytes.concat(encodeAliceVote, encodeBobVote);

        // initial salt for accumulator from `propose` in `GovernorCounting`
        bytes32 ballotBoxAccum = bytes32(proposalId);
        ballotBoxAccum = sha256(bytes.concat(ballotBoxAccum, encodeAliceVote));
        bytes32 finalBallotBoxAccum = sha256(bytes.concat(ballotBoxAccum, encodeBobVote));

        return (finalBallotBoxAccum, encodedBallots);
    }

    function _createProposalParams()
        internal
        pure
        returns (address[] memory, uint256[] memory, bytes[] memory, string memory)
    {
        address[] memory targets = new address[](1);
        targets[0] = address(0x4);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("doSomething()");
        string memory description = "Do something";

        return (targets, values, calldatas, description);
    }
}
