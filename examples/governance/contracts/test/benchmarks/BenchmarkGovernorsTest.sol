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
import {BaselineGovernor} from "../../src/BaselineGovernor.sol";
import {RiscZeroGovernor} from "../../src/RiscZeroGovernor.sol";
import {BenchmarkTestBase} from "./BenchmarkTestBase.sol";
import {VoteToken} from "../../src/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {Strings} from "openzeppelin/contracts/utils/Strings.sol";
import {ImageID} from "../../src/ImageID.sol";
import {RiscZeroMockVerifier, Receipt as VerifierReceipt} from "risc0/test/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract BenchmarkGovernorsTest is Test, BenchmarkTestBase {
    function setUp() public override {
        super.setUp();
    }

    function testFuzz_BaselineWorkflow(uint16 numAccounts) public {
        vm.pauseGasMetering();
        numAccounts = uint16(bound(numAccounts, 100, 1000));

        // Generate accounts and mint tokens
        generateAccounts(numAccounts);
        for (uint256 i = 0; i < numAccounts; i++) {
            address currentAddress = accounts[i];
            voteToken.mint(currentAddress, 100);
            vm.prank(currentAddress);
            voteToken.delegate(currentAddress);
        }
        vm.resumeGasMetering();

        // metering for output
        uint256 gasUsed = gasleft();

        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();

        baselineProposalId = baselineGovernor.propose(targets, values, calldatas, description);

        generateSignatures(baselineProposalId, numAccounts, true);

        // move to active voting period
        vm.roll(block.number + baselineGovernor.votingDelay() + 1);

        // cast votes
        uint256 expectedForVotes = 0;
        for (uint256 i = 0; i < numAccounts; i++) {
            baselineGovernor.castVoteBySig(baselineProposalId, forSupport, accounts[i], baselineSignatures[accounts[i]]);

            expectedForVotes += 100; // Each account has 100 voting power
            vm.roll(block.number + 1);
        }

        // Move to end of voting period
        vm.roll(block.number + baselineGovernor.votingPeriod() + 1);

        // execute proposal
        baselineGovernor.execute(targets, values, calldatas, keccak256(bytes(description)));

        gasUsed = gasUsed - gasleft();
        vm.writeLine(
            "contracts/test/benchmarks/gas_data.csv",
            string(abi.encodePacked("BaselineGovernor,", vm.toString(numAccounts), ",", vm.toString(gasUsed)))
        );

        assertEq(
            uint256(baselineGovernor.state(baselineProposalId)),
            uint256(IGovernor.ProposalState.Executed),
            "Proposal should be executed"
        );
    }

    function testFuzz_RiscZeroWorkflow(uint16 numAccounts) public {
        vm.pauseGasMetering();
        numAccounts = uint16(bound(numAccounts, 100, 1000));

        // Generate accounts and mint tokens
        generateAccounts(numAccounts);
        for (uint256 i = 0; i < numAccounts; i++) {
            address currentAddress = accounts[i];
            voteToken.mint(currentAddress, 100);
            vm.prank(currentAddress);
            voteToken.delegate(currentAddress);
        }
        vm.resumeGasMetering();

        // metering for output
        uint256 gasUsed = gasleft();

        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) =
            _createProposalParams();

        uint256 proposalId = riscZeroGovernor.propose(targets, values, calldatas, description);

        // move to active voting period
        vm.roll(block.number + riscZeroGovernor.votingDelay() + 1);

        // cast votes
        for (uint256 i = 0; i < numAccounts; i++) {
            vm.prank(accounts[i]);
            riscZeroGovernor.castVote(proposalId, forSupport);
            vm.roll(block.number + 1);
        }

        // get journal digest
        bytes32 journalDigest = getJournalDigest(proposalId, numAccounts);

        // mock prove
        VerifierReceipt memory receipt = mockVerifier.mockProve(ImageID.FINALIZE_VOTES_ID, journalDigest);

        // mock call to verifier called in verifyAndFinalizeVotes()
        address verifierAddress = riscZeroGovernor.verifier.address;
        bytes memory expectedCalldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, receipt.seal, IMAGE_ID, journalDigest);

        vm.mockCall(verifierAddress, expectedCalldata, abi.encode());

        // Move to end of voting period
        vm.roll(block.number + riscZeroGovernor.votingPeriod() + 1);

        // call `verifyAndFinalizeVotes` and assert expectations
        bytes memory journal = getJournal(proposalId, numAccounts);
        riscZeroGovernor.verifyAndFinalizeVotes(receipt.seal, journal);

        // Offsetting gas by real verification cost for more accurate benchmarks
        gasUsed += 250000;

        // execute proposal
        riscZeroGovernor.execute(targets, values, calldatas, keccak256(bytes(description)));

        gasUsed = gasUsed - gasleft();
        vm.writeLine(
            "contracts/test/benchmarks/gas_data.csv",
            string(abi.encodePacked("RiscZeroGovernor,", vm.toString(numAccounts), ",", vm.toString(gasUsed)))
        );

        assertEq(
            uint256(riscZeroGovernor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed),
            "Proposal should be executed"
        );
    }
}
