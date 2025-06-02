// Copyright 2025 RISC Zero, Inc.
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

pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";

import {Steel, Beacon, Encoding} from "../steel/Steel.sol";

contract SteelVerifier {
    function validateCommitment(Steel.Commitment memory commitment) external view returns (bool) {
        return Steel.validateCommitment(commitment);
    }
}

contract SteelTest is Test {
    SteelVerifier internal verifier;

    function setUp() public {
        verifier = new SteelVerifier();
    }

    function createCommitment(uint240 claimID, uint16 version, bytes32 digest)
        internal
        pure
        returns (Steel.Commitment memory)
    {
        return
            Steel.Commitment({id: Encoding.encodeVersionedID(claimID, version), digest: digest, configID: bytes32(0)});
    }

    function test_ValidateCommitment_V0_Block_Success() public {
        vm.roll(block.number + 10);
        uint256 targetBlockNumber = block.number - 5;
        bytes32 targetBlockHash = blockhash(targetBlockNumber);
        assertTrue(targetBlockHash != bytes32(0), "Test setup: blockhash(target) is zero");

        Steel.Commitment memory c = createCommitment(uint240(targetBlockNumber), 0, targetBlockHash);
        assertTrue(verifier.validateCommitment(c), "V0 valid block commitment failed");
    }

    function test_ValidateCommitment_V0_Block_WrongHash() public {
        vm.roll(block.number + 10);
        uint256 targetBlockNumber = block.number - 5;
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong_hash"));
        assertTrue(blockhash(targetBlockNumber) != bytes32(0), "Test setup: blockhash(target) is zero");

        Steel.Commitment memory c = createCommitment(uint240(targetBlockNumber), 0, wrongHash);
        assertFalse(verifier.validateCommitment(c), "V0 wrong block hash should be invalid");
    }

    function test_ValidateCommitment_V0_Block_TooOld() public {
        vm.roll(block.number + 300);
        uint256 oldBlockNumber = 1;
        bytes32 someHash = keccak256(abi.encodePacked("some_hash"));

        Steel.Commitment memory c = createCommitment(uint240(oldBlockNumber), 0, someHash);
        vm.expectPartialRevert(Steel.CommitmentTooOld.selector);
        verifier.validateCommitment(c);
    }

    function test_ValidateCommitment_V1_Beacon_Success() public {
        uint256 timestamp = 1700000000;
        bytes32 expectedRoot = keccak256(abi.encodePacked("beacon_root_v1"));

        // Mock the call to Beacon.BEACON_ROOTS_ADDRESS
        vm.mockCall(Beacon.BEACON_ROOTS_ADDRESS, abi.encode(timestamp), abi.encode(expectedRoot));

        Steel.Commitment memory c = createCommitment(
            uint240(timestamp), // claimID is timestamp for V1
            1,
            expectedRoot
        );
        assertTrue(verifier.validateCommitment(c), "V1 valid beacon commitment failed");
    }

    function test_ValidateCommitment_V1_Beacon_WrongRoot() public {
        uint256 timestamp = 1700000000;
        bytes32 correctRoot = keccak256(abi.encodePacked("beacon_root_v1"));
        bytes32 wrongRootInCommitment = keccak256(abi.encodePacked("wrong_root"));

        // Mock the call to Beacon.BEACON_ROOTS_ADDRESS to return the correctRoot
        vm.mockCall(Beacon.BEACON_ROOTS_ADDRESS, abi.encode(timestamp), abi.encode(correctRoot));

        Steel.Commitment memory c = createCommitment(
            uint240(timestamp),
            1,
            wrongRootInCommitment // Commitment has the wrong root
        );
        assertFalse(verifier.validateCommitment(c), "V1 wrong beacon root should be invalid");
    }

    function test_ValidateCommitment_V1_Beacon_InvalidTimestamp() public {
        uint256 invalidTimestamp = 1700000001;

        // Mock the call to Beacon.BEACON_ROOTS_ADDRESS to revert
        vm.mockCallRevert(
            Beacon.BEACON_ROOTS_ADDRESS,
            abi.encode(invalidTimestamp),
            bytes("Mocked EIP-4788 Revert for invalid timestamp")
        );

        Steel.Commitment memory c =
            createCommitment(uint240(invalidTimestamp), 1, keccak256(abi.encodePacked("any_root")));
        vm.expectRevert(Beacon.InvalidBlockTimestamp.selector);
        verifier.validateCommitment(c);
    }

    function test_ValidateCommitment_V2_Reverts_ConsensusSlotNotSupported() public {
        uint240 claimID = 999;
        Steel.Commitment memory c = createCommitment(claimID, 2, keccak256(abi.encodePacked("any_digest_v2")));
        vm.expectRevert(Steel.ConsensusSlotCommitmentNotSupported.selector);
        verifier.validateCommitment(c);
    }

    function test_ValidateCommitment_V3_Reverts_InvalidCommitmentVersion() public {
        uint240 claimID = 1000;
        Steel.Commitment memory c = createCommitment(
            claimID,
            3, // Any version > 2 not explicitly handled
            keccak256(abi.encodePacked("any_digest_v3"))
        );
        vm.expectRevert(Steel.InvalidCommitmentVersion.selector);
        verifier.validateCommitment(c);
    }
}
