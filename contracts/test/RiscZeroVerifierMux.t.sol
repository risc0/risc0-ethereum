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
import {RiscZeroVerifierMux} from "../src/RiscZeroVerifierMux.sol";
import {TestReceipt} from "./TestReceipt.sol";

contract RiscZeroVerifierEmergencyStopTest is Test {
    using OutputLib for Output;
    using ReceiptClaimLib for ReceiptClaim;

    bytes32 internal TEST_JOURNAL_DIGEST = sha256(TestReceipt.JOURNAL);
    ReceiptClaim internal TEST_RECEIPT_CLAIM =
        ReceiptClaimLib.from(TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
    RiscZeroReceipt internal TEST_RECEIPT_A;
    RiscZeroReceipt internal TEST_RECEIPT_B;
    RiscZeroReceipt internal TEST_MANGLED_RECEIPT_A;
    RiscZeroReceipt internal TEST_MANGLED_RECEIPT_B;
    bytes4 internal SELECTOR_A;
    bytes4 internal SELECTOR_B;

    RiscZeroMockVerifier internal verifierMockA;
    RiscZeroMockVerifier internal verifierMockB;
    RiscZeroVerifierMux internal verifierMux;

    function setUp() external {
        verifierMux = new RiscZeroVerifierMux();

        verifierMockA = new RiscZeroMockVerifier(bytes4(0));
        verifierMockB = new RiscZeroMockVerifier(bytes4(uint32(1)));

        TEST_RECEIPT_A = verifierMockA.mockProve(TEST_RECEIPT_CLAIM.digest());
        TEST_RECEIPT_B = verifierMockB.mockProve(TEST_RECEIPT_CLAIM.digest());

        TEST_MANGLED_RECEIPT_A = TEST_RECEIPT_A;
        TEST_MANGLED_RECEIPT_A.seal[4] ^= bytes1(uint8(1));
        TEST_MANGLED_RECEIPT_B = TEST_RECEIPT_B;
        TEST_MANGLED_RECEIPT_B.seal[4] ^= bytes1(uint8(1));

        SELECTOR_A = verifierMockA.SELECTOR();
        SELECTOR_B = verifierMockB.SELECTOR();
    }

    function test_EmptyMuxVerifyIntegrity() external {
        // Expect no calls to be made to the verifier controlled.
        vm.expectCall(address(verifierMockA), new bytes(0), 0);
        vm.expectCall(address(verifierMockB), new bytes(0), 0);

        // Empty mux should always revert with selector unknown.
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorUnknown.selector, SELECTOR_A));
        verifierMux.verifyIntegrity(TEST_RECEIPT_A);

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorUnknown.selector, SELECTOR_B));
        verifierMux.verifyIntegrity(TEST_RECEIPT_B);
    }

    function test_SingleVerifierVerifyIntegrity() external {
        // Expect exactly 2 calls, to verifier A with TEST_RECEIPT_A and TEST_MANGLED_RECEIPT_A.
        vm.expectCall(address(verifierMockA), new bytes(0), 2);
        vm.expectCall(address(verifierMockA), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_RECEIPT_A), 1);
        vm.expectCall(
            address(verifierMockA), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_MANGLED_RECEIPT_A), 1
        );
        vm.expectCall(address(verifierMockB), new bytes(0), 0);

        verifierMux.addVerifier(SELECTOR_A, verifierMockA);

        verifierMux.verifyIntegrity(TEST_RECEIPT_A);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verifyIntegrity(TEST_MANGLED_RECEIPT_A);

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorUnknown.selector, SELECTOR_B));
        verifierMux.verifyIntegrity(TEST_RECEIPT_B);
    }

    function test_TwoVerifiersVerifyIntegrity() external {
        // Expect exactly 2 calls, to verifier A/B with TEST_RECEIPT_x and TEST_MANGLED_RECEIPT_x.
        vm.expectCall(address(verifierMockA), new bytes(0), 2);
        vm.expectCall(address(verifierMockA), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_RECEIPT_A), 1);
        vm.expectCall(
            address(verifierMockA), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_MANGLED_RECEIPT_A), 1
        );
        vm.expectCall(address(verifierMockB), new bytes(0), 2);
        vm.expectCall(address(verifierMockB), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_RECEIPT_B), 1);
        vm.expectCall(
            address(verifierMockB), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_MANGLED_RECEIPT_B), 1
        );

        verifierMux.addVerifier(SELECTOR_A, verifierMockA);
        verifierMux.addVerifier(SELECTOR_B, verifierMockB);

        verifierMux.verifyIntegrity(TEST_RECEIPT_A);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verifyIntegrity(TEST_MANGLED_RECEIPT_A);

        verifierMux.verifyIntegrity(TEST_RECEIPT_B);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verifyIntegrity(TEST_MANGLED_RECEIPT_B);
    }

    function test_RemoveVerifierVerifyIntegrity() external {
        // Expect exactly 4 calls to verifier A with TEST_RECEIPT_A and TEST_MANGLED_RECEIPT_A.
        // Expect exactly 2 calls to verifier B with TEST_RECEIPT_B and TEST_MANGLED_RECEIPT_B.
        vm.expectCall(address(verifierMockA), new bytes(0), 4);
        vm.expectCall(address(verifierMockA), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_RECEIPT_A), 2);
        vm.expectCall(
            address(verifierMockA), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_MANGLED_RECEIPT_A), 2
        );
        vm.expectCall(address(verifierMockB), new bytes(0), 2);
        vm.expectCall(address(verifierMockB), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_RECEIPT_B), 1);
        vm.expectCall(
            address(verifierMockB), abi.encodeCall(IRiscZeroVerifier.verifyIntegrity, TEST_MANGLED_RECEIPT_B), 1
        );

        verifierMux.addVerifier(SELECTOR_A, verifierMockA);
        verifierMux.addVerifier(SELECTOR_B, verifierMockB);

        verifierMux.verifyIntegrity(TEST_RECEIPT_A);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verifyIntegrity(TEST_MANGLED_RECEIPT_A);

        verifierMux.verifyIntegrity(TEST_RECEIPT_B);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verifyIntegrity(TEST_MANGLED_RECEIPT_B);

        verifierMux.removeVerifier(SELECTOR_B);

        verifierMux.verifyIntegrity(TEST_RECEIPT_A);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verifyIntegrity(TEST_MANGLED_RECEIPT_A);

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorRemoved.selector, SELECTOR_B));
        verifierMux.verifyIntegrity(TEST_RECEIPT_B);
    }

    function test_EmptyMuxVerify() external {
        // Expect no calls to be made to the verifier controlled.
        vm.expectCall(address(verifierMockA), new bytes(0), 0);
        vm.expectCall(address(verifierMockB), new bytes(0), 0);

        // Empty mux should always revert with selector unknown.
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorUnknown.selector, SELECTOR_A));
        verifierMux.verify(TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorUnknown.selector, SELECTOR_B));
        verifierMux.verify(TEST_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
    }

    function test_SingleVerifierVerify() external {
        // Expect exactly 2 calls, to verifier A with TEST_RECEIPT_A and TEST_MANGLED_RECEIPT_A.
        vm.expectCall(address(verifierMockA), new bytes(0), 2);
        vm.expectCall(
            address(verifierMockA),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );
        vm.expectCall(
            address(verifierMockA),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_MANGLED_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );
        vm.expectCall(address(verifierMockB), new bytes(0), 0);

        verifierMux.addVerifier(SELECTOR_A, verifierMockA);

        verifierMux.verify(TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verify(
            TEST_MANGLED_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST
        );

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorUnknown.selector, SELECTOR_B));
        verifierMux.verify(TEST_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
    }

    function test_TwoVerifiersVerify() external {
        // Expect exactly 2 calls, to verifier A/B with TEST_RECEIPT_x and TEST_MANGLED_RECEIPT_x.
        vm.expectCall(address(verifierMockA), new bytes(0), 2);
        vm.expectCall(
            address(verifierMockA),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );
        vm.expectCall(
            address(verifierMockA),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_MANGLED_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );
        vm.expectCall(address(verifierMockB), new bytes(0), 2);
        vm.expectCall(
            address(verifierMockB),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );
        vm.expectCall(
            address(verifierMockB),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_MANGLED_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );

        verifierMux.addVerifier(SELECTOR_A, verifierMockA);
        verifierMux.addVerifier(SELECTOR_B, verifierMockB);

        verifierMux.verify(TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verify(
            TEST_MANGLED_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST
        );

        verifierMux.verify(TEST_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verify(
            TEST_MANGLED_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST
        );
    }

    function test_RemoveVerifierVerify() external {
        // Expect exactly 4 calls to verifier A with TEST_RECEIPT_A and TEST_MANGLED_RECEIPT_A.
        // Expect exactly 2 calls to verifier B with TEST_RECEIPT_B and TEST_MANGLED_RECEIPT_B.
        vm.expectCall(address(verifierMockA), new bytes(0), 4);
        vm.expectCall(
            address(verifierMockA),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            2
        );
        vm.expectCall(
            address(verifierMockA),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_MANGLED_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            2
        );
        vm.expectCall(address(verifierMockB), new bytes(0), 2);
        vm.expectCall(
            address(verifierMockB),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );
        vm.expectCall(
            address(verifierMockB),
            abi.encodeCall(
                IRiscZeroVerifier.verify,
                (TEST_MANGLED_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST)
            ),
            1
        );

        verifierMux.addVerifier(SELECTOR_A, verifierMockA);
        verifierMux.addVerifier(SELECTOR_B, verifierMockB);

        verifierMux.verify(TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verify(
            TEST_MANGLED_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST
        );

        verifierMux.verify(TEST_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verify(
            TEST_MANGLED_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST
        );

        verifierMux.removeVerifier(SELECTOR_B);

        verifierMux.verify(TEST_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
        vm.expectRevert(VerificationFailed.selector);
        verifierMux.verify(
            TEST_MANGLED_RECEIPT_A.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST
        );

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorRemoved.selector, SELECTOR_B));
        verifierMux.verify(TEST_RECEIPT_B.seal, TestReceipt.IMAGE_ID, TestReceipt.POST_DIGEST, TEST_JOURNAL_DIGEST);
    }

    function test_OnlyOwnerCanAddVerifier() external {
        verifierMux.addVerifier(SELECTOR_A, verifierMockA);

        verifierMux.renounceOwnership();

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifierMux.addVerifier(SELECTOR_B, verifierMockB);
    }

    function test_OnlyOwnerCanRemoveVerifier() external {
        verifierMux.addVerifier(SELECTOR_A, verifierMockA);

        verifierMux.renounceOwnership();

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifierMux.removeVerifier(SELECTOR_A);
    }

    function test_VerifierCanOnlyBeAddedOnce() external {
        verifierMux.addVerifier(SELECTOR_A, verifierMockA);

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorInUse.selector, SELECTOR_A));
        verifierMux.addVerifier(SELECTOR_A, verifierMockA);
    }

    function test_VerifierCannotBeAddedAfterRemove() external {
        verifierMux.addVerifier(SELECTOR_A, verifierMockA);
        verifierMux.removeVerifier(SELECTOR_A);

        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorRemoved.selector, SELECTOR_A));
        verifierMux.addVerifier(SELECTOR_A, verifierMockA);
    }

    function test_UnsetVerifierCannotBeRemoved() external {
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifierMux.SelectorUnknown.selector, SELECTOR_A));
        verifierMux.removeVerifier(SELECTOR_A);
    }
}
