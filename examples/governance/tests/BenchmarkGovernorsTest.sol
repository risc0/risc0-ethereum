// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {BaselineGovernor} from "../contracts/BaselineGovernor.sol";
import {RiscZeroGovernor} from "../contracts/RiscZeroGovernor.sol";
import {VoteToken} from "../contracts/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {ImageID} from "../contracts/utils/ImageID.sol";
import {RiscZeroMockVerifier, Receipt as VerifierReceipt} from "../contracts/groth16/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "../contracts/groth16/IRiscZeroVerifier.sol";

contract BenchmarkGovernorsTest is Test {
    BaselineGovernor public baselineGovernor;
    RiscZeroGovernor public riscZeroGovernor;
    VoteToken public voteToken;
    RiscZeroMockVerifier public mockVerifier;

    address public alice;
    uint8 public forSupport = 1;
    uint8 public againstSupport = 1;
    address public bob;
    address public charlie;
    address public voterOneAddress;
    address public voterTwoAddress;
    uint256 public voterOnePk;
    uint256 public voterTwoPk;
    bytes32 public constant IMAGE_ID = ImageID.FINALIZE_VOTES_ID;
    bytes4 public constant MOCK_SELECTOR = bytes4(uint32(1337));

    function setUp() public {
        voteToken = new VoteToken();
        mockVerifier = new RiscZeroMockVerifier(MOCK_SELECTOR);
        baselineGovernor = new BaselineGovernor(voteToken);
        riscZeroGovernor = new RiscZeroGovernor(
            voteToken,
            IMAGE_ID,
            mockVerifier
        );

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

        (voterOneAddress, voterOnePk) = makeAddrAndKey("voter_one");
        (voterTwoAddress, voterTwoPk) = makeAddrAndKey("voter_two");
    }

    function testBaselineWorkflow() public {
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

        // set up two voters with PKs
        vm.prank(alice);
        voteToken.transfer(voterOneAddress, 50);
        vm.prank(alice);
        voteToken.transfer(voterTwoAddress, 50);

        vm.prank(voterOneAddress);
        voteToken.delegate(voterOneAddress);
        vm.prank(voterTwoAddress);
        voteToken.delegate(voterTwoAddress);

        // get signatures
        bytes memory signatureOne = getSignature(
            forSupport,
            proposalId,
            voterOneAddress,
            voterOnePk
        );
        bytes memory signatureTwo = getSignature(
            forSupport,
            proposalId,
            voterTwoAddress,
            voterTwoPk
        );

        // move to active voting period
        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // cast votes
        baselineGovernor.castVoteBySig(
            proposalId,
            forSupport,
            voterOneAddress,
            signatureOne
        );

        vm.roll(block.number + 1);

        baselineGovernor.castVoteBySig(
            proposalId,
            forSupport,
            voterTwoAddress,
            signatureTwo
        );

        // Move to end of voting period
        vm.roll(block.number + baselineGovernor.votingPeriod() + 1);

        // execute proposal
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

    function testRiscZeroWorkflow() public {
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

        // move to active voting period
        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // cast votes
        vm.prank(alice);
        riscZeroGovernor.castVote(proposalId, forSupport);

        vm.prank(bob);
        riscZeroGovernor.castVote(proposalId, forSupport);

        // get journal digest
        bytes32 journalDigest = getJournalDigest(proposalId);

        // mock prove
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

        // Move to end of voting period
        vm.roll(block.number + baselineGovernor.votingPeriod() + 1);
        
        // call `verifyAndFinalizeVotes` and assert expectations
        bytes memory journal = getJournal(proposalId);
        riscZeroGovernor.verifyAndFinalizeVotes(receipt.seal, journal);


        // execute proposal
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

    }

    function getSignature(
        uint8 support,
        uint256 proposalId,
        address signer,
        uint256 privateKey
    ) public noGasMetering returns (bytes memory signature) {
        bytes32 digest = baselineGovernor.voteHash(proposalId, support, signer);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function getJournalDigest(
        uint256 proposalId
    ) public noGasMetering returns (bytes32 journalDigest) {
        (
            bytes32 finalBallotBoxAccum,
            bytes memory encodedBallots
        ) = generateBallotBoxCommit(forSupport, forSupport);

        // encode journal and hash
        bytes memory journal = abi.encodePacked(
            proposalId,
            finalBallotBoxAccum,
            // abi.encode(alice, uint8(1), bob, uint8(0))
            encodedBallots
        );

        journalDigest = sha256(journal);
    }

    function getJournal(
        uint256 proposalId
    ) public noGasMetering returns (bytes memory journal) {
        (
            bytes32 finalBallotBoxAccum,
            bytes memory encodedBallots
        ) = generateBallotBoxCommit(forSupport, forSupport);

        // encode journal and hash
        journal = abi.encodePacked(
            proposalId,
            finalBallotBoxAccum,
            // abi.encode(alice, uint8(1), bob, uint8(0))
            encodedBallots
        );
    }

    function generateBallotBoxCommit(
        uint8 aliceSupport_,
        uint8 bobSupport_
    ) internal noGasMetering returns (bytes32, bytes memory) {
        // Prepare the journal and receipt for verifyAndFinalizeVotes
        bytes memory encodeAliceVote = abi.encodePacked(
            uint16(0),
            aliceSupport_,
            uint8(0),
            alice
        );
        bytes memory encodeBobVote = abi.encodePacked(
            uint16(0),
            bobSupport_,
            uint8(0),
            bob
        );
        bytes memory encodedBallots = bytes.concat(
            encodeAliceVote,
            encodeBobVote
        );

        bytes32 ballotBoxAccum = 0x296dc540e823507aa12a2e7be3c9c01672a7d9bb7840214223e8758fdb2986c7;
        ballotBoxAccum = sha256(bytes.concat(ballotBoxAccum, encodeAliceVote));

        bytes32 finalBallotBoxAccum = sha256(
            bytes.concat(ballotBoxAccum, encodeBobVote)
        );

        return (finalBallotBoxAccum, encodedBallots);
    }

    // function createBaselineProposal() public returns (uint256 proposalId) {
    //     (
    //         address[] memory targets,
    //         uint256[] memory values,
    //         bytes[] memory calldatas,
    //         string memory description
    //     ) = _createProposalParams();

    //     proposalId = baselineGovernor.propose(
    //         targets,
    //         values,
    //         calldatas,
    //         description
    //     );
    // }

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
}
