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

import {
    IRiscZeroVerifier,
    Output,
    OutputLib,
    // Receipt needs to be renamed due to collision with type on the Test contract.
    Receipt as RiscZeroReceipt,
    ReceiptClaim,
    ReceiptClaimLib,
    ExitCode,
    SystemExitCode
} from "../src/IRiscZeroVerifier.sol";
import {MockRiscZeroVerifier} from "../src/test/MockRiscZeroVerifier.sol";
import {RiscZeroVerifierEmergencyStop} from "../src/RiscZeroVerifierEmergencyStop.sol";
import {TestReceipt} from "./TestReceipt.sol";

contract RiscZeroVerifierEmergencyStopTest is Test {
    using OutputLib for Output;
    using ReceiptClaimLib for ReceiptClaim;

    MockRiscZeroVerifier internal verifier;
    RiscZeroVerifierEmergencyStop internal verifierEstop;

    ReceiptClaim internal TEST_RECEIPT_CLAIM = ReceiptClaim(
        TestReceipt.IMAGE_ID,
        TestReceipt.POST_DIGEST,
        ExitCode(SystemExitCode.Halted, 0),
        bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
        Output(sha256(TestReceipt.JOURNAL), bytes32(0)).digest()
    );
    RiscZeroReceipt internal TEST_RECEIPT;

    function setUp() external {
        verifier = new MockRiscZeroVerifier(bytes32(0));
        verifierEstop = new RiscZeroVerifierEmergencyStop(verifier);

        TEST_RECEIPT = verifier.mockProve(TEST_RECEIPT_CLAIM.digest());
    }

    function testNormalOperation() external view {
        require(verifierEstop.verify(TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, sha256(TestReceipt.JOURNAL)), "verify failed under normal operation");
        require(verifierEstop.verifyIntegrity(TEST_RECEIPT), "verifyIntegrity failed under normal operation");
    }
}
