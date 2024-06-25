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
    ExitCode,
    IRiscZeroVerifier,
    Output,
    OutputLib,
    // Receipt needs to be renamed due to collision with type on the Test contract.
    Receipt as RiscZeroReceipt,
    ReceiptClaim,
    ReceiptClaimLib,
    SystemExitCode,
    SystemState,
    SystemStateLib,
    VerificationFailed
} from "../src/IRiscZeroVerifier.sol";
import {ControlID, RiscZeroGroth16Verifier} from "../src/groth16/RiscZeroGroth16Verifier.sol";
import {RiscZeroVerifierEmergencyStop} from "../src/RiscZeroVerifierEmergencyStop.sol";
import {RiscZeroVerifierRouter} from "../src/RiscZeroVerifierRouter.sol";
import {TestReceipt} from "./TestReceipt.sol";

contract EndToEnd is Test {
    using OutputLib for Output;
    using ReceiptClaimLib for ReceiptClaim;
    using SystemStateLib for SystemState;

    ReceiptClaim internal TEST_RECEIPT_CLAIM = ReceiptClaim(
        TestReceipt.IMAGE_ID,
        SystemState(0, bytes32(0)).digest(),
        ExitCode(SystemExitCode.Halted, 0),
        bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
        Output(sha256(TestReceipt.JOURNAL), bytes32(0)).digest()
    );

    RiscZeroReceipt internal TEST_RECEIPT = RiscZeroReceipt(TestReceipt.SEAL, TEST_RECEIPT_CLAIM.digest());

    RiscZeroVerifierRouter internal verifierRouter;

    RiscZeroGroth16Verifier internal verifier;
    RiscZeroVerifierEmergencyStop internal verifierEstop;

    function setUp() external {
        verifierRouter = new RiscZeroVerifierRouter(address(this));

        verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        verifierEstop = new RiscZeroVerifierEmergencyStop(verifier, address(this));

        verifierRouter.addVerifier(verifier.SELECTOR(), verifier);
    }

    function testVerifyKnownGoodReceipt() external view {
        verifierRouter.verifyIntegrity(TEST_RECEIPT);
    }

    function testVerifyKnownGoodImageIdAndJournal() external view {
        verifierRouter.verify(TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, sha256(TestReceipt.JOURNAL));
    }
}
