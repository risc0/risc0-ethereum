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
import {VoteToken} from "../../src/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {Strings} from "openzeppelin/contracts/utils/Strings.sol";
import {ImageID} from "../../src/ImageID.sol";
import {RiscZeroMockVerifier} from "risc0/test/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract BenchmarkTestBase is Test {
    BaselineGovernor public baselineGovernor;
    RiscZeroGovernor public riscZeroGovernor;
    VoteToken public voteToken;
    RiscZeroMockVerifier public mockVerifier;

    uint8 public forSupport = 1;
    address[] public accounts;
    uint256 public baselineProposalId;
    uint256 public riscZeroProposalId;
    mapping(address => bytes) public baselineSignatures;
    mapping(address => bytes) public riscZeroSignatures;
    mapping(address => uint256) public keys;
    bytes32 public constant IMAGE_ID = ImageID.FINALIZE_VOTES_ID;
    bytes4 public constant MOCK_SELECTOR = bytes4(uint32(1337));

    function setUp() public virtual {
        voteToken = new VoteToken();
        mockVerifier = new RiscZeroMockVerifier(MOCK_SELECTOR);
        baselineGovernor = new BaselineGovernor(voteToken);
        riscZeroGovernor = new RiscZeroGovernor(voteToken, IMAGE_ID, mockVerifier);
    }

    function generateAccounts(uint256 noOfAccounts) public noGasMetering {
        for (uint256 i = 0; i < noOfAccounts; i++) {
            string memory base = string(abi.encodePacked("yolo", Strings.toString(i)));
            (address tempAddress, uint256 tempPk) = makeAddrAndKey(base);
            accounts.push(tempAddress);
            keys[tempAddress] = tempPk;
        }
    }

    function getSignature(uint8 support, uint256 proposalId, address signer, uint256 privateKey)
        internal
        noGasMetering
        returns (bytes memory signature)
    {
        bytes32 digest = baselineGovernor.voteHash(proposalId, support, signer);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function generateSignatures(uint256 proposalId, uint256 noOfSignatures, bool isBaseline) internal noGasMetering {
        for (uint256 i = 0; i < noOfSignatures; i++) {
            address currentAddress = accounts[i];
            bytes memory signature = getSignature(forSupport, proposalId, currentAddress, keys[currentAddress]);

            if (isBaseline) {
                baselineSignatures[currentAddress] = signature;
            } else {
                riscZeroSignatures[currentAddress] = signature;
            }
        }
    }

    function getJournal(uint256 proposalId, uint256 noOfAccounts)
        internal
        noGasMetering
        returns (bytes memory journal)
    {
        (bytes32 finalBallotBoxAccum, bytes memory encodedBallots) = hashBallots(noOfAccounts, proposalId);

        journal = abi.encodePacked(proposalId, finalBallotBoxAccum, encodedBallots);
    }

    function getJournalDigest(uint256 proposalId, uint256 noOfAccounts)
        internal
        noGasMetering
        returns (bytes32 journalDigest)
    {
        bytes memory journal = getJournal(proposalId, noOfAccounts);
        journalDigest = sha256(journal);
    }

    function hashBallots(uint256 noOfAccounts, uint256 proposalId)
        internal
        noGasMetering
        returns (bytes32, bytes memory)
    {
        bytes memory encodedBallots;
        bytes32 ballotHash = bytes32(proposalId);

        // Prepare the journal and receipt for verifyAndFinalizeVotes
        for (uint256 i = 0; i < noOfAccounts; i++) {
            address currentAddress = accounts[i];

            bytes memory encodedVote = abi.encodePacked(uint16(0), forSupport, uint8(0), currentAddress);

            encodedBallots = bytes.concat(encodedBallots, encodedVote);
            ballotHash = sha256(bytes.concat(ballotHash, encodedVote));
        }

        return (ballotHash, encodedBallots);
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
