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

pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Ownable} from "openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "openzeppelin/contracts/utils/Pausable.sol";

import {
    IRiscZeroVerifier,
    Output,
    OutputLib,
    // Receipt needs to be renamed due to collision with type on the Test contract.
    Receipt as RiscZeroReceipt,
    ReceiptClaim,
    ReceiptClaimLib,
    ExitCode,
    SystemExitCode,
    VerificationFailed
} from "../src/IRiscZeroVerifier.sol";
import {RiscZeroMockVerifier} from "../src/test/RiscZeroMockVerifier.sol";
import {RiscZeroVerifierEmergencyStop} from "../src/RiscZeroVerifierEmergencyStop.sol";
import {TestReceipt} from "./TestReceipt.sol";

contract RiscZeroVerifierEmergencyStopTest is Test {
    using OutputLib for Output;
    using ReceiptClaimLib for ReceiptClaim;

    RiscZeroMockVerifier internal verifierMock;
    RiscZeroVerifierEmergencyStop internal verifierEstop;

    bytes32 internal TEST_JOURNAL_DIGEST = sha256(TestReceipt.JOURNAL);
    ReceiptClaim internal TEST_RECEIPT_CLAIM = ReceiptClaimLib.ok(TestReceipt.IMAGE_ID, TEST_JOURNAL_DIGEST);
    RiscZeroReceipt internal TEST_RECEIPT;

    function setUp() external {
        verifierMock = new RiscZeroMockVerifier(bytes4(0));
        verifierEstop = new RiscZeroVerifierEmergencyStop(verifierMock, address(this));

        TEST_RECEIPT = verifierMock.mockProve(TEST_RECEIPT_CLAIM.digest());
    }

    function test_NormalOperation() external view {
        verifierEstop.verify(TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, TEST_JOURNAL_DIGEST);
        verifierEstop.verifyIntegrity(TEST_RECEIPT);
    }

    function test_RevertsWhenStopped() external {
        // Sanity check to make sure the contract started out working as expected.
        verifierEstop.verify(TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, TEST_JOURNAL_DIGEST);
        verifierEstop.verifyIntegrity(TEST_RECEIPT);

        verifierEstop.estop();

        // Now expect calls to verify to fail with an error indicating that the contract is paused.
        vm.expectRevert(Pausable.EnforcedPause.selector);
        verifierEstop.verify(TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, TEST_JOURNAL_DIGEST);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        verifierEstop.verifyIntegrity(TEST_RECEIPT);
    }

    function test_OnlyOwnerCanEstopWithoutProof() external {
        verifierEstop.renounceOwnership();

        // Without an owner, trying to call estop() should revert.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifierEstop.estop();
    }

    function test_EstopRequiresValidProofOfExploit() external {
        verifierEstop.renounceOwnership();

        RiscZeroReceipt memory proofOfExploit = verifierMock.mockProve(bytes32(0));

        // Ensure that using a valid receipt for a non-exploit execution results in a revert.
        vm.expectRevert(RiscZeroVerifierEmergencyStop.InvalidProofOfExploit.selector);
        verifierEstop.estop(TEST_RECEIPT);

        RiscZeroReceipt memory mangledProofOfExploit = proofOfExploit;
        mangledProofOfExploit.seal[4] ^= bytes1(uint8(1));
        vm.expectRevert(VerificationFailed.selector);
        verifierEstop.estop(mangledProofOfExploit);
    }

    function test_AnyoneCanEstopWithProofOfExploit() external {
        verifierEstop.renounceOwnership();

        RiscZeroReceipt memory proofOfExploit = verifierMock.mockProve(bytes32(0));
        verifierEstop.estop(proofOfExploit);

        // Now expect calls to verify to fail with an error indicating that the contract is paused.
        vm.expectRevert(Pausable.EnforcedPause.selector);
        verifierEstop.verify(TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, TEST_JOURNAL_DIGEST);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        verifierEstop.verifyIntegrity(TEST_RECEIPT);
    }

    function test_TransferEstopOwnership() external {
        address newOwner = address(0xc0ffee);

        verifierEstop.transferOwnership(newOwner);
        assertEq(verifierEstop.pendingOwner(), newOwner);
        assertEq(verifierEstop.owner(), address(this));

        vm.startPrank(newOwner);
        verifierEstop.acceptOwnership();
        vm.stopPrank();

        assertEq(verifierEstop.owner(), newOwner);
    }
}
