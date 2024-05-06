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
import {ControlID, RiscZeroGroth16Verifier} from "../src/groth16/RiscZeroGroth16Verifier.sol";
import {TestReceipt} from "./TestReceipt.sol";

contract RiscZeroGroth16VerifierTest is Test {
    using OutputLib for Output;
    using ReceiptClaimLib for ReceiptClaim;

    ReceiptClaim internal TEST_RECEIPT_CLAIM = ReceiptClaim(
        TestReceipt.IMAGE_ID,
        TestReceipt.POST_DIGEST,
        ExitCode(SystemExitCode.Halted, 0),
        bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
        Output(sha256(TestReceipt.JOURNAL), bytes32(0)).digest()
    );

    RiscZeroReceipt internal TEST_RECEIPT = RiscZeroReceipt(TestReceipt.SEAL, TEST_RECEIPT_CLAIM.digest());

    RiscZeroGroth16Verifier internal verifier;

    function setUp() external {
        verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
    }

    function testVerifyKnownGoodReceipt() external view {
        require(verifier.verifyIntegrity(TEST_RECEIPT), "verification failed");
    }

    function testVerifyKnownGoodImageIdAndJournal() external view {
        require(
            verifier.verify(
                TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, TEST_RECEIPT_CLAIM.postStateDigest, sha256(TestReceipt.JOURNAL)
            ),
            "verification failed"
        );
    }

    // A no-so-thorough test to make sure changing the bits causes a failure.
    function testVerifyMangledReceipts() external view {
        ReceiptClaim memory mangled_claim = TEST_RECEIPT_CLAIM;
        bytes memory mangled_seal = TEST_RECEIPT.seal;

        mangled_seal[4] ^= bytes1(uint8(1));
        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest())),
            "verification passed on mangled seal value"
        );
        mangled_seal = TEST_RECEIPT.seal;

        mangled_claim.preStateDigest ^= bytes32(uint256(1));
        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest())),
            "verification passed on mangled preStateDigest value"
        );
        mangled_claim = TEST_RECEIPT_CLAIM;

        mangled_claim.postStateDigest ^= bytes32(uint256(1));
        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest())),
            "verification passed on mangled postStateDigest value"
        );
        mangled_claim = TEST_RECEIPT_CLAIM;

        mangled_claim.exitCode = ExitCode(SystemExitCode.SystemSplit, 0);
        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest())),
            "verification passed on mangled exitCode value"
        );
        mangled_claim = TEST_RECEIPT_CLAIM;

        mangled_claim.input ^= bytes32(uint256(1));
        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest())),
            "verification passed on mangled input value"
        );
        mangled_claim = TEST_RECEIPT_CLAIM;

        mangled_claim.output ^= bytes32(uint256(1));
        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest())),
            "verification passed on mangled output value"
        );
        mangled_claim = TEST_RECEIPT_CLAIM;

        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest() ^ bytes32(uint256(1)))),
            "verification passed on mangled claim digest value (low bit)"
        );

        require(
            !verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest() ^ bytes32(uint256(1) << 255))),
            "verification passed on mangled claim digest value (high bit)"
        );

        // Just a quick sanity check
        require(verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, mangled_claim.digest())), "verification failed");
    }

    function testSelectorIsStable() external view {
        require(verifier.SELECTOR() == hex"7beca612");
    }
}
