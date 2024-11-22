// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TestUtils} from "./TestUtils.sol";
import {
    IRiscZeroVerifier, Receipt as RiscZeroReceipt, ReceiptClaimLib, ReceiptClaim
} from "../src/IRiscZeroVerifier.sol";
import {RiscZeroMockVerifier} from "../src/test/RiscZeroMockVerifier.sol";
import {IRiscZeroSetVerifier} from "../src/IRiscZeroSetVerifier.sol";
import {RiscZeroSetVerifier} from "../src/RiscZeroSetVerifier.sol";

contract RiscZeroSetVerifierTest is Test {
    using ReceiptClaimLib for ReceiptClaim;
    using TestUtils for RiscZeroSetVerifier;

    bytes32 constant SET_BUILDER_IMAGE_ID = 0x0000000000000000000000000000000000000000000000000000005e7b011de7;
    bytes32 constant APP_IMAGE_ID = 0x000000000000000000000000000000000000000000000000000000000000ec80;

    RiscZeroMockVerifier public verifier;
    RiscZeroSetVerifier public setVerifier;

    function mockProveRoot(bytes32 root) internal view returns (RiscZeroReceipt memory) {
        return verifier.mockProve(SET_BUILDER_IMAGE_ID, sha256(abi.encodePacked(SET_BUILDER_IMAGE_ID, root)));
    }

    function submitRoot(bytes32 root) internal {
        vm.expectEmit(true, true, true, true);
        emit IRiscZeroSetVerifier.VerifiedRoot(root);
        setVerifier.submitMerkleRoot(root, mockProveRoot(root).seal);
        require(setVerifier.containsRoot(root), "set verifier does not contain submitted root");
    }

    function setUp() public {
        verifier = new RiscZeroMockVerifier(bytes4(0));
        setVerifier = new RiscZeroSetVerifier(verifier, SET_BUILDER_IMAGE_ID, "https://dev.null");
    }

    function testFuzz_CompletenessCachedRoot(bytes32[] memory claimDigests) public {
        vm.assume(claimDigests.length > 0);
        (bytes32 root, bytes32[][] memory tree) = TestUtils.computeMerkleTree(claimDigests);
        submitRoot(root);

        TestUtils.Proof[] memory proofs = TestUtils.computeProofs(tree);

        for (uint256 i = 0; i < proofs.length; i++) {
            setVerifier.verifyIntegrity(
                RiscZeroReceipt({seal: setVerifier.encodeSeal(proofs[i]), claimDigest: claimDigests[i]})
            );
        }
    }

    function testFuzz_CompletenessInlineRoot(bytes32[] memory claimDigests) public view {
        vm.assume(claimDigests.length > 0);
        (bytes32 root, bytes32[][] memory tree) = TestUtils.computeMerkleTree(claimDigests);
        RiscZeroReceipt memory rootReceipt = mockProveRoot(root);

        TestUtils.Proof[] memory proofs = TestUtils.computeProofs(tree);

        bytes memory rootSeal = rootReceipt.seal;
        for (uint256 i = 0; i < proofs.length; i++) {
            setVerifier.verifyIntegrity(
                RiscZeroReceipt({seal: setVerifier.encodeSeal(proofs[i], rootSeal), claimDigest: claimDigests[i]})
            );
        }
    }

    function testFuzz_Verify(bytes32[] memory claimDigests, uint8 verifyIndex) public {
        vm.assume(claimDigests.length > 0);
        vm.assume(claimDigests.length < 256);
        vm.assume(verifyIndex < claimDigests.length);

        // Replace one of the random claim digests with a claim digest with a known journal.
        bytes memory journal = bytes("some arbitrary bytes");
        ReceiptClaim memory claim = ReceiptClaimLib.ok(APP_IMAGE_ID, sha256(journal));
        claimDigests[verifyIndex] = claim.digest();

        (bytes32 root, bytes32[][] memory tree) = TestUtils.computeMerkleTree(claimDigests);
        submitRoot(root);

        TestUtils.Proof[] memory proofs = TestUtils.computeProofs(tree);
        setVerifier.verify(setVerifier.encodeSeal(proofs[verifyIndex]), APP_IMAGE_ID, sha256(journal));
    }

    function test_SubmitFailsForInvalidRootSeal() public {
        bytes32 root = bytes32(uint256(0xdeadbeef));
        RiscZeroReceipt memory receipt = mockProveRoot(root);

        // Check that submitRoot initially passes.
        uint256 snapshot = vm.snapshot();
        setVerifier.submitMerkleRoot(root, receipt.seal);
        vm.revertTo(snapshot);

        bytes memory revertReason = bytes("mock verification failure");
        vm.mockCallRevert(address(verifier), abi.encodePacked(IRiscZeroVerifier.verify.selector), revertReason);
        vm.expectRevert(revertReason);
        setVerifier.submitMerkleRoot(root, receipt.seal);
    }

    function test_VerifyFailsWithInvalidRootSeal() public {
        bytes32[] memory claimDigests = new bytes32[](3);
        claimDigests[0] = hex"1eaf00";
        claimDigests[1] = hex"1eaf01";
        claimDigests[2] = hex"1eaf02";

        (bytes32 root, bytes32[][] memory tree) = TestUtils.computeMerkleTree(claimDigests);
        RiscZeroReceipt memory receipt = mockProveRoot(root);
        TestUtils.Proof[] memory proofs = TestUtils.computeProofs(tree);

        // Check that submitRoot initially passes.
        bytes memory seal = setVerifier.encodeSeal(proofs[1], receipt.seal);
        uint256 snapshot = vm.snapshot();
        setVerifier.verifyIntegrity(RiscZeroReceipt({seal: seal, claimDigest: claimDigests[1]}));
        vm.revertTo(snapshot);

        bytes memory revertReason = bytes("mock verification failure");
        vm.mockCallRevert(address(verifier), abi.encodePacked(IRiscZeroVerifier.verify.selector), revertReason);
        vm.expectRevert(revertReason);
        setVerifier.verifyIntegrity(RiscZeroReceipt({seal: seal, claimDigest: claimDigests[1]}));
    }

    function test_VerifyFailsWithNoRoot() public {
        bytes32[] memory claimDigests = new bytes32[](3);
        claimDigests[0] = hex"1eaf00";
        claimDigests[1] = hex"1eaf01";
        claimDigests[2] = hex"1eaf02";

        (bytes32 root, bytes32[][] memory tree) = TestUtils.computeMerkleTree(claimDigests);
        RiscZeroReceipt memory receipt = mockProveRoot(root);
        TestUtils.Proof[] memory proofs = TestUtils.computeProofs(tree);

        // Check that submitRoot initially passes.
        bytes memory seal = setVerifier.encodeSeal(proofs[1]);
        uint256 snapshot = vm.snapshot();
        setVerifier.submitMerkleRoot(root, receipt.seal);
        setVerifier.verifyIntegrity(RiscZeroReceipt({seal: seal, claimDigest: claimDigests[1]}));
        vm.revertTo(snapshot);

        // Run it again, skipping the step to submit the root.
        vm.expectRevert();
        setVerifier.verifyIntegrity(RiscZeroReceipt({seal: seal, claimDigest: claimDigests[1]}));
    }
}
