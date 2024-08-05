// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {BaselineGovernor} from "../contracts/BaselineGovernor.sol";
import {VoteToken} from "../contracts/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";

contract BaselineGovernorTest is Test {
    BaselineGovernor public baselineGovernor;
    VoteToken public voteToken;
    address public alice;
    address public bob;
    address public charlie;
    address public voterAddress;
    uint256 public voterPk;

    function setUp() public {
        voteToken = new VoteToken();
        baselineGovernor = new BaselineGovernor(voteToken);

        alice = vm.addr(1);
        bob = vm.addr(2);
        charlie = vm.addr(3);

        // mint some tokens and delegate
        voteToken.mint(alice, 100);
        voteToken.mint(bob, 50);
        voteToken.mint(charlie, 30);

        vm.prank(alice);
        voteToken.delegate(alice);
        vm.prank(bob);
        voteToken.delegate(bob);
        vm.prank(charlie);
        voteToken.delegate(charlie);

        // instantiate new voter + PK for signing
        (voterAddress, voterPk) = makeAddrAndKey("voter");
    }

    function testProposalCreation() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();

        uint256 proposalId = baselineGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        assertGt(proposalId, 0, "Proposal should be created with non-zero ID");
        assertEq(
            uint256(baselineGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Pending),
            "New proposal should be in Pending state"
        );
    }

    function testProposalThreshold() public {
        uint256 proposalThreshold = baselineGovernor.proposalThreshold();

        // Try to create a proposal with Charlie (who has 30 tokens)
        vm.prank(charlie);
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );
        assertGt(proposalId, 0, "Proposal should be created with non-zero ID");

        // Now try with Alice (who has 100 tokens) with different parameters
        vm.prank(alice);
        (
            address[] memory targets2,
            uint256[] memory values2,
            bytes[] memory calldatas2,
            string memory description2
        ) = _createProposalParams();
        targets2[0] = address(0x5); // Change target address
        description2 = "Do something else"; // Change description
        uint256 proposalId2 = baselineGovernor.propose(
            targets2,
            values2,
            calldatas2,
            description2
        );
        assertGt(
            proposalId2,
            0,
            "Second proposal should be created with non-zero ID"
        );
        assertNotEq(
            proposalId,
            proposalId2,
            "Proposal IDs should be different"
        );
    }

    function testVoting() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        // Move to active state
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);

        vm.prank(alice);
        baselineGovernor.castVote(proposalId, 1); // Vote in favor

        vm.prank(bob);
        baselineGovernor.castVote(proposalId, 0); // Vote against

        (
            uint256 againstVotes,
            uint256 forVotes,
            uint256 abstainVotes
        ) = baselineGovernor.proposalVotes(proposalId);
        assertEq(forVotes, 100, "For votes should be 100");
        assertEq(againstVotes, 50, "Against votes should be 50");
        assertEq(abstainVotes, 0, "Abstain votes should be 0");
    }

    function testVotingBySignature() public {
        // Create a proposal
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();

        uint256 proposalId = baselineGovernor.propose(
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

        // Move to active state
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);

        // Prepare vote data
        uint8 support = 1; // 1 for 'For'

        // Generate the vote hash
        bytes32 digest = baselineGovernor.voteHash(
            proposalId,
            support,
            voterAddress
        );

        // Sign the vote hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(voterPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Cast vote by signature
        baselineGovernor.castVoteBySig(
            proposalId,
            support,
            voterAddress,
            signature
        );

        // Check the vote was counted
        (
            uint256 againstVotes,
            uint256 forVotes,
            uint256 abstainVotes
        ) = baselineGovernor.proposalVotes(proposalId);

        assertEq(forVotes, 100, "For votes should be 100");
    }

    function testQuorumAndExecution() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

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

        baselineGovernor.execute(
            targets,
            values,
            calldatas,
            keccak256(bytes(description))
        );
        assertEq(
            uint256(baselineGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed),
            "Proposal should be executed"
        );
    }

    function testFailToReachQuorum() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();
        uint256 proposalId = baselineGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );

        // Move to active state
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);

        // Only Bob votes, which isn't enough to reach quorum
        vm.prank(bob);
        baselineGovernor.castVote(proposalId, 1);

        // Move to end of voting period
        vm.roll(block.number + baselineGovernor.votingPeriod() + 1);

        assertEq(
            uint256(baselineGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated),
            "Proposal should be defeated due to not reaching quorum"
        );
    }

    function _createProposalParams()
        internal
        pure
        returns (
            address[] memory,
            uint256[] memory,
            bytes[] memory,
            string memory
        )
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

    // gas only measured for proposal, a single vote, and execution
    // we need proper gas benchmarking for a significant no. of votes
    function testGasMeasurements() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory calldatas,
            string memory description
        ) = _createProposalParams();

        uint256 gasBefore = gasleft();
        uint256 proposalId = baselineGovernor.propose(
            targets,
            values,
            calldatas,
            description
        );
        uint256 gasAfter = gasleft();
        console2.log("Gas used for proposal creation:", gasBefore - gasAfter);

        // Move to active state
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);

        gasBefore = gasleft();
        vm.prank(alice);
        baselineGovernor.castVote(proposalId, 1);
        gasAfter = gasleft();
        console2.log("Gas used for casting a vote:", gasBefore - gasAfter);

        // Move to end of voting period
        vm.roll(block.number + baselineGovernor.votingPeriod() + 1);

        gasBefore = gasleft();
        baselineGovernor.execute(
            targets,
            values,
            calldatas,
            keccak256(bytes(description))
        );
        gasAfter = gasleft();
        console2.log(
            "Gas used for executing a proposal:",
            gasBefore - gasAfter
        );
    }
}
