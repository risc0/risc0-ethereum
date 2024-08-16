// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {BaselineGovernor} from "../contracts/BaselineGovernor.sol";
import {RiscZeroGovernor} from "../contracts/RiscZeroGovernor.sol";
import {VoteToken} from "../contracts/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {Strings} from "openzeppelin/contracts/utils/Strings.sol";
import {ImageID} from "../contracts/utils/ImageID.sol";
import {RiscZeroMockVerifier, Receipt as VerifierReceipt} from "../contracts/groth16/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "../contracts/groth16/IRiscZeroVerifier.sol";

contract BenchmarkGovernorsTest is Test {
    BaselineGovernor public baselineGovernor;
    RiscZeroGovernor public riscZeroGovernor;
    VoteToken public voteToken;
    RiscZeroMockVerifier public mockVerifier;

    uint8 public forSupport = 1;
    uint8 public againstSupport = 1;
    address[] public addresses;
    address public owner;
    address public alice;
    address public bob;
    address public voterOneAddress;
    address public voterTwoAddress;
    uint256 public voterOnePk;
    uint256 public voterTwoPk;
    mapping(address => bytes) public signatures;
    mapping(address => uint256) public keys;
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
        owner = vm.addr(3);

        voteToken.mint(alice, 100);
        voteToken.mint(bob, 50);

        vm.prank(alice);
        voteToken.delegate(alice);
        vm.prank(bob);
        voteToken.delegate(bob);

        (voterOneAddress, voterOnePk) = makeAddrAndKey("voter_one");
        (voterTwoAddress, voterTwoPk) = makeAddrAndKey("voter_two");
    }

    function testBaselineManySigs() public {
        uint256 noOfAccounts = 10;

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

        // generate accounts
        generateAccounts(noOfAccounts);

        // mint and delegate these accounts ERC20 token for voting power
        for (uint256 i = 0; i < noOfAccounts; i++) {
            address currentAddress = addresses[i];
            voteToken.mint(currentAddress, 100);
            vm.prank(currentAddress);
            voteToken.delegate(currentAddress);
        }

        // generate signatures
        generateSignatures(proposalId);

        // move to active voting period
        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // cast votes
        for (uint256 i = 0; i < noOfAccounts; i++) {
            address currentAddress = addresses[i];
            baselineGovernor.castVoteBySig(
                proposalId,
                forSupport,
                currentAddress,
                signatures[currentAddress]
            );

            vm.roll(block.number + 1);
        }

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
        vm.startPrank(alice);
        voteToken.transfer(voterOneAddress, 50);
        voteToken.transfer(voterTwoAddress, 50);
        vm.stopPrank();

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

    function generateAccounts(uint256 noOfAccounts) public noGasMetering {
        for (uint256 i = 0; i < noOfAccounts; i++) {
            string memory base = string(
                abi.encodePacked("yolo", Strings.toString(i))
            );
            (address tempAddress, uint256 tempPk) = makeAddrAndKey(base);
            addresses.push(tempAddress);
            keys[tempAddress] = tempPk;
        }
    }

    function generateSignatures(uint256 proposalId) public noGasMetering {
        for (uint256 i = 0; i < addresses.length; i++) {
            address currentAddress = addresses[i];
            signatures[currentAddress] = getSignature(
                forSupport,
                proposalId,
                currentAddress,
                keys[currentAddress]
            );
        }
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
