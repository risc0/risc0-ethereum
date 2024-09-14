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
import {GovernorTestBase} from "./GovernorTestBase.sol";
import {RiscZeroGovernor} from "../src/RiscZeroGovernor.sol";
import {VoteToken} from "../src/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {ImageID} from "../src/ImageID.sol";
import {RiscZeroMockVerifier, Receipt as VerifierReceipt} from "risc0/test/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract RiscZeroGovernorTest is Test, GovernorTestBase {
    uint8 public aliceSupport;
    uint8 public bobSupport;
    uint8 public charlieSupport;

    event CommittedBallot(uint256 indexed proposalId, bytes encoded);

    struct ProposalVote {
        bool finalized;
        bytes32 ballotBoxCommit;
        uint256 againstVotes;
        uint256 forVotes;
        uint256 abstainVotes;
    }

    function setUp() public override {
        super.setUp();
    }

    function testProposalCreation() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();

        uint256 proposalId = riscZeroGovernor.propose(targets, values, calldatas, description);

        assertGt(proposalId, 0, "Proposal should be created with non-zero ID");
        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Pending),
            "New proposal should be in Pending state"
        );
    }

    function testVoting() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();
        uint256 proposalId = riscZeroGovernor.propose(targets, values, calldatas, description);

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        aliceSupport = 1; // Vote in favor
        vm.prank(alice);
        vm.expectEmit();
        emit VoteCast(alice, proposalId, aliceSupport, 0, "");
        riscZeroGovernor.castVote(proposalId, aliceSupport);

        bobSupport = 0; // Vote against
        vm.prank(bob);
        vm.expectEmit();
        emit VoteCast(bob, proposalId, bobSupport, 0, "");
        riscZeroGovernor.castVote(proposalId, bobSupport);
    }

    function testVotingBySignature() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();
        uint256 proposalId = riscZeroGovernor.propose(targets, values, calldatas, description);

        // Transfer tokens from alice to the new voter address
        vm.prank(alice);
        voteToken.transfer(voterAddress, 100);

        // Delegate voting power
        vm.prank(voterAddress);
        voteToken.delegate(voterAddress);

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        uint8 forSupport = 1; // 1 for 'For'

        bytes32 digest = riscZeroGovernor.voteHash(proposalId, forSupport, voterAddress);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(voterPk, digest);
        bytes memory signature = abi.encode(r, s, v);

        bytes memory encoded = abi.encodePacked(uint16(1), forSupport, v, r, s, digest);

        vm.expectEmit();
        emit CommittedBallot(proposalId, encoded);
        riscZeroGovernor.castVoteBySig(proposalId, forSupport, voterAddress, signature);
    }

    function testVerifyAndFinalizeVotes() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();

        uint256 proposalId = riscZeroGovernor.propose(targets, values, calldatas, description);

        aliceSupport = 1;
        bobSupport = 0;

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        vm.prank(alice);
        riscZeroGovernor.castVote(proposalId, aliceSupport);

        vm.prank(bob);
        riscZeroGovernor.castVote(proposalId, bobSupport);

        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        (bytes32 finalBallotBoxAccum, bytes memory encodedBallots) = hashBallots(aliceSupport, bobSupport, proposalId);

        bytes memory journal = abi.encodePacked(proposalId, finalBallotBoxAccum, encodedBallots);

        // create mock receipt
        bytes32 journalDigest = sha256(journal);
        VerifierReceipt memory receipt = mockVerifier.mockProve(ImageID.FINALIZE_VOTES_ID, journalDigest);

        // mock call to verifier called in verifyAndFinalizeVotes()
        address verifierAddress = riscZeroGovernor.verifier.address;
        bytes4 verifySelector = IRiscZeroVerifier.verify.selector;
        bytes memory expectedCalldata = abi.encodeWithSelector(verifySelector, receipt.seal, IMAGE_ID, journalDigest);

        vm.mockCall(verifierAddress, expectedCalldata, abi.encode());

        riscZeroGovernor.verifyAndFinalizeVotes(receipt.seal, journal);
        (uint256 againstVotes, uint256 forVotes, uint256 abstainVotes) = riscZeroGovernor.proposalVotes(proposalId);

        assertEq(forVotes, 100, "For votes should be 100");
        assertEq(againstVotes, 50, "Against votes should be 50");
        assertEq(abstainVotes, 0, "Abstain votes should be 0");

        vm.clearMockedCalls();
    }

    function testQuorumAndExecution() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();

        uint256 proposalId = riscZeroGovernor.propose(targets, values, calldatas, description);

        aliceSupport = 1;
        bobSupport = 1;

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // Cast votes
        vm.prank(alice);
        riscZeroGovernor.castVote(proposalId, 1);
        vm.prank(bob);
        riscZeroGovernor.castVote(proposalId, 1);

        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        (bytes32 finalBallotBoxAccum, bytes memory encodedBallots) = hashBallots(aliceSupport, bobSupport, proposalId);

        bytes memory journal = abi.encodePacked(proposalId, finalBallotBoxAccum, encodedBallots);
        bytes32 journalDigest = sha256(journal);

        VerifierReceipt memory receipt = mockVerifier.mockProve(ImageID.FINALIZE_VOTES_ID, journalDigest);

        // Mock the verifier call
        address verifierAddress = riscZeroGovernor.verifier.address;
        bytes4 verifySelector = IRiscZeroVerifier.verify.selector;
        bytes memory expectedCalldata = abi.encodeWithSelector(verifySelector, receipt.seal, IMAGE_ID, journalDigest);
        vm.mockCall(verifierAddress, expectedCalldata, abi.encode());

        // Call verifyAndFinalizeVotes
        riscZeroGovernor.verifyAndFinalizeVotes(receipt.seal, journal);

        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Succeeded),
            "Proposal should have succeeded"
        );

        riscZeroGovernor.execute(targets, values, calldatas, keccak256(bytes(description)));
        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed),
            "Proposal should be executed"
        );

        vm.clearMockedCalls();
    }

    function testQuorumNotReached() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();
        uint256 proposalId = riscZeroGovernor.propose(targets, values, calldatas, description);

        charlieSupport = 1;

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // Only Bob votes, which isn't enough to reach quorum
        vm.prank(charlie);
        riscZeroGovernor.castVote(proposalId, 1);

        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        bytes memory encodeCharlieVote = abi.encodePacked(uint16(0), charlieSupport, uint8(0), charlie);
        bytes memory encodedBallots = encodeCharlieVote;

        // hashBallots supports only two votes
        // so we recreate it just with one vote from Charlie here
        bytes32 ballotBoxAccum = bytes32(proposalId);
        bytes32 finalBallotBoxAccum = sha256(bytes.concat(ballotBoxAccum, encodeCharlieVote));

        bytes memory journal = abi.encodePacked(proposalId, finalBallotBoxAccum, encodedBallots);
        bytes32 journalDigest = sha256(journal);

        VerifierReceipt memory receipt = mockVerifier.mockProve(ImageID.FINALIZE_VOTES_ID, journalDigest);

        // Mock the verifier call
        address verifierAddress = riscZeroGovernor.verifier.address;
        bytes4 verifySelector = IRiscZeroVerifier.verify.selector;
        bytes memory expectedCalldata = abi.encodeWithSelector(verifySelector, receipt.seal, IMAGE_ID, journalDigest);
        vm.mockCall(verifierAddress, expectedCalldata, abi.encode());

        // Call verifyAndFinalizeVotes
        riscZeroGovernor.verifyAndFinalizeVotes(receipt.seal, journal);

        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated),
            "Proposal should be defeated due to not reaching quorum"
        );
    }
}
