// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {GovernorTestBase} from "./GovernorTestBase.sol";
import {console2} from "forge-std/console2.sol";
import {RiscZeroGovernor} from "../contracts/RiscZeroGovernor.sol";
import {VoteToken} from "../contracts/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {ImageID} from "../contracts/utils/ImageID.sol";
import {RiscZeroMockVerifier, Receipt as VerifierReceipt} from "risc0/test/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract RiscZeroGovernorTest is Test, GovernorTestBase {
    uint8 public aliceSupport;
    uint8 public bobSupport;

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
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();

        uint256 proposalId = riscZeroGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        assertGt(proposalId, 0, "Proposal should be created with non-zero ID");
        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Pending),
            "New proposal should be in Pending state"
        );
    }

    function testVoting() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();
        uint256 proposalId = riscZeroGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        aliceSupport = 1;
        vm.prank(alice);
        vm.expectEmit();
        emit VoteCast(alice, proposalId, aliceSupport, 0, "");
        riscZeroGovernor.castVote(proposalId, aliceSupport); // Vote in favor

        bobSupport = 0;
        vm.prank(bob);
        vm.expectEmit();
        emit VoteCast(bob, proposalId, bobSupport, 0, "");
        riscZeroGovernor.castVote(proposalId, bobSupport); // Vote against
    }

    function testVotingBySignature() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();
        uint256 proposalId = riscZeroGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        // Transfer tokens from alice to the new voter address
        vm.prank(alice);
        voteToken.transfer(voterAddress, 100);

        // Delegate voting power
        vm.prank(voterAddress);
        voteToken.delegate(voterAddress);

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        uint8 forSupport = 1; // 1 for 'For'

        bytes32 digest = riscZeroGovernor.voteHash(
            proposalId,
            forSupport,
            voterAddress
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(voterPk, digest);
        bytes memory signature = abi.encode(r, s, v);

        bytes memory encoded = abi.encodePacked(
            uint16(1),
            forSupport,
            v,
            r,
            s,
            digest
        );

        vm.expectEmit();
        emit CommittedBallot(proposalId, encoded);
        riscZeroGovernor.castVoteBySig(
            proposalId,
            forSupport,
            voterAddress,
            signature
        ); // Vote in favor

        //move forward after vote
        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        // riscZeroGovernor.castVoteBySig(proposalId, bobSupport, bob); // Vote against

        // Note: We can't check vote counts here as they're not immediately updated in RiscZeroGovernor
        // We'll need to finalize votes to see the results
    }

    function testVerifyAndFinalizeVotes() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();

        uint256 proposalId = riscZeroGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        aliceSupport = 1;
        bobSupport = 0;

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        vm.prank(alice);
        riscZeroGovernor.castVote(proposalId, aliceSupport);

        vm.prank(bob);
        riscZeroGovernor.castVote(proposalId, bobSupport);

        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        (
            bytes32 finalBallotBoxAccum,
            bytes memory encodedBallots
        ) = hashBallots(aliceSupport, bobSupport);

        // encode journal and hash
        bytes memory journal = abi.encodePacked(
            proposalId,
            finalBallotBoxAccum,
            // abi.encode(alice, uint8(1), bob, uint8(0))
            encodedBallots
        );

        // create journalDigest and `mockProve` to create receipt.
        bytes32 journalDigest = sha256(journal);
        VerifierReceipt memory receipt = mockVerifier.mockProve(
            ImageID.FINALIZE_VOTES_ID,
            journalDigest
        );

        // mock call to verifier called in verifyAndFinalizeVotes()
        address verifierAddress = riscZeroGovernor.verifier.address;
        bytes4 verifySelector = IRiscZeroVerifier.verify.selector;
        bytes memory expectedCalldata = abi.encodeWithSelector(
            verifySelector,
            receipt.seal,
            IMAGE_ID,
            journalDigest
        );

        vm.mockCall(verifierAddress, expectedCalldata, abi.encode());

        // call `verifyAndFinalizeVotes` and assert expectations
        riscZeroGovernor.verifyAndFinalizeVotes(receipt.seal, journal);
        (
            uint256 againstVotes,
            uint256 forVotes,
            uint256 abstainVotes
        ) = riscZeroGovernor.proposalVotes(proposalId);

        assertEq(forVotes, 100, "For votes should be 100");
        assertEq(againstVotes, 50, "Against votes should be 50");
        assertEq(abstainVotes, 0, "Abstain votes should be 0");

        vm.clearMockedCalls();
    }

    function testQuorumAndExecution() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();

        uint256 proposalId = riscZeroGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        aliceSupport = 1;
        bobSupport = 1;

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // Cast votes
        vm.prank(alice);
        riscZeroGovernor.castVote(proposalId, 1);
        vm.prank(bob);
        riscZeroGovernor.castVote(proposalId, 1);

        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        (
            bytes32 finalBallotBoxAccum,
            bytes memory encodedBallots
        ) = hashBallots(aliceSupport, bobSupport);

        bytes memory journal = abi.encodePacked(
            proposalId,
            finalBallotBoxAccum,
            encodedBallots
        );
        bytes32 journalDigest = sha256(journal);

        VerifierReceipt memory receipt = mockVerifier.mockProve(
            ImageID.FINALIZE_VOTES_ID,
            journalDigest
        );

        // Mock the verifier call
        address verifierAddress = riscZeroGovernor.verifier.address;
        bytes4 verifySelector = IRiscZeroVerifier.verify.selector;
        bytes memory expectedCalldata = abi.encodeWithSelector(
            verifySelector,
            receipt.seal,
            IMAGE_ID,
            journalDigest
        );
        vm.mockCall(verifierAddress, expectedCalldata, abi.encode());

        // Call verifyAndFinalizeVotes
        riscZeroGovernor.verifyAndFinalizeVotes(receipt.seal, journal);

        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Succeeded),
            "Proposal should have succeeded"
        );

        riscZeroGovernor.execute(
            targets,
            values,
            calldatas,
            keccak256(bytes(description))
        );
        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed),
            "Proposal should be executed"
        );

        vm.clearMockedCalls();
    }

    function testFailToReachQuorum() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();
        uint256 proposalId = riscZeroGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // Only Bob votes, which isn't enough to reach quorum
        vm.prank(bob);
        riscZeroGovernor.castVote(proposalId, 1);

        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        // _mockVerifyAndFinalizeVotes(proposalId);

        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated),
            "Proposal should be defeated due to not reaching quorum"
        );
    }

}
