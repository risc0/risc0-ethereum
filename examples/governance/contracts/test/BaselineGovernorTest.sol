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
import {GovernorTestBase} from "./GovernorTestBase.sol";
import {console2} from "forge-std/console2.sol";
import {BaselineGovernor} from "../src/BaselineGovernor.sol";
import {VoteToken} from "../src/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";

contract BaselineGovernorTest is Test, GovernorTestBase {
    function setUp() public override {
        super.setUp();
    }

    function testProposalCreation() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();

        uint256 proposalId = baselineGovernor.propose(targets, values, calldatas, description);

        assertGt(proposalId, 0, "Proposal should be created with non-zero ID");
        assertEq(
            uint256(baselineGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Pending),
            "New proposal should be in Pending state"
        );
    }

    function testProposalIDs() public {
        // Try to create a proposal with Charlie (who has 30 tokens)
        vm.prank(charlie);
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(targets, values, calldatas, description);
        assertGt(proposalId, 0, "Proposal should be created with non-zero ID");

        // Now try with Alice (who has 100 tokens) with different parameters
        vm.prank(alice);
        (address[] memory targets2, uint256[] memory values2, bytes[] memory calldatas2, string memory description2) =
            _createProposalParams();
        targets2[0] = address(0x5); // Change target address
        description2 = "Do something else"; // Change description
        uint256 proposalId2 = baselineGovernor.propose(targets2, values2, calldatas2, description2);
        assertGt(proposalId2, 0, "Second proposal should be created with non-zero ID");
        assertNotEq(proposalId, proposalId2, "Proposal IDs should be different");
    }

    function testVoting() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(targets, values, calldatas, description);

        // Move to active state
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);

        vm.prank(alice);
        baselineGovernor.castVote(proposalId, 1); // Vote in favor

        vm.prank(bob);
        baselineGovernor.castVote(proposalId, 0); // Vote against

        (uint256 againstVotes, uint256 forVotes, uint256 abstainVotes) = baselineGovernor.proposalVotes(proposalId);
        assertEq(forVotes, 100, "For votes should be 100");
        assertEq(againstVotes, 50, "Against votes should be 50");
        assertEq(abstainVotes, 0, "Abstain votes should be 0");
    }

    function testVotingBySignature() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();

        uint256 proposalId = baselineGovernor.propose(targets, values, calldatas, description);

        // Transfer tokens from alice to the new voter address
        vm.prank(alice);
        voteToken.transfer(voterAddress, 100);

        // Delegate voting power
        vm.prank(voterAddress);
        voteToken.delegate(voterAddress);

        // Move to active state
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);

        // Prepare vote data
        uint8 support = 1; // 1 for 'For'

        // Generate the vote hash
        bytes32 digest = baselineGovernor.voteHash(proposalId, support, voterAddress);

        // Sign the vote hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(voterPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Cast vote by signature
        baselineGovernor.castVoteBySig(proposalId, support, voterAddress, signature);

        // Check the vote was counted
        (, uint256 forVotes,) = baselineGovernor.proposalVotes(proposalId);

        assertEq(forVotes, 100, "For votes should be 100");
    }

    function testQuorumAndExecution() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(targets, values, calldatas, description);

        // Move to active state and vote
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);
        vm.prank(alice);
        baselineGovernor.castVote(proposalId, 1);
        vm.prank(bob);
        baselineGovernor.castVote(proposalId, 1);

        // Move to end of voting period
        vm.roll(block.number + baselineGovernor.votingPeriod() + 1);

        assertEq(
            uint256(baselineGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Succeeded),
            "Proposal should have succeeded"
        );

        baselineGovernor.execute(targets, values, calldatas, keccak256(bytes(description)));
        assertEq(
            uint256(baselineGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed),
            "Proposal should be executed"
        );
    }

    function testQuorumNotReached() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(targets, values, calldatas, description);

        // Move to active state and vote
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);
        vm.prank(charlie);
        baselineGovernor.castVote(proposalId, 1);

        // Move to end of voting period
        vm.roll(block.number + baselineGovernor.votingPeriod() + 1);

        assertEq(
            uint256(baselineGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated),
            "Proposal should be defeated due to not reaching quorum"
        );
    }
}
