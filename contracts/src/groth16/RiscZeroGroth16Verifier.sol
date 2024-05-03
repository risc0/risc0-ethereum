// Copyright 2024 RISC Zero, Inc.
//
// The RiscZeroGroth16Verifier is a free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// The RiscZeroGroth16Verifier is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
// Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// the RiscZeroGroth16Verifier. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;

import {SafeCast} from "openzeppelin/contracts/utils/math/SafeCast.sol";

import {ControlID} from "./ControlID.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";
import {
    ExitCode,
    IRiscZeroVerifier,
    Output,
    OutputLib,
    Receipt,
    ReceiptClaim,
    ReceiptClaimLib,
    SystemExitCode
} from "../IRiscZeroVerifier.sol";

/// @notice reverse the byte order of the uint256 value.
/// @dev Solidity uses a big-endian ABI encoding. Reversing the byte order before encoding
/// ensure that the encoded value will be little-endian.
/// Written by k06a. https://ethereum.stackexchange.com/a/83627
function reverseByteOrderUint256(uint256 input) pure returns (uint256 v) {
    v = input;

    // swap bytes
    v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
        | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

    // swap 2-byte long pairs
    v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
        | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

    // swap 4-byte long pairs
    v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
        | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

    // swap 8-byte long pairs
    v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
        | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

    // swap 16-byte long pairs
    v = (v >> 128) | (v << 128);
}

/// @notice reverse the byte order of the uint32 value.
/// @dev Solidity uses a big-endian ABI encoding. Reversing the byte order before encoding
/// ensure that the encoded value will be little-endian.
/// Written by k06a. https://ethereum.stackexchange.com/a/83627
function reverseByteOrderUint32(uint32 input) pure returns (uint32 v) {
    v = input;

    // swap bytes
    v = ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);

    // swap 2-byte long pairs
    v = (v >> 16) | (v << 16);
}

/// @notice A Groth16 seal over the claimed receipt claim.
struct Seal {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}

/// @notice Groth16 verifier contract for RISC Zero receipts of execution.
contract RiscZeroGroth16Verifier is IRiscZeroVerifier, Groth16Verifier {
    using ReceiptClaimLib for ReceiptClaim;
    using OutputLib for Output;
    using SafeCast for uint256;

    /// @notice Control ID hash for the identity_p254 predicate decomposed by `splitDigest`.
    /// @dev This value controls what set of recursion programs, and therefore what version of the
    /// zkVM circuit, will be accepted by this contract. Each instance of this verifier contract
    /// will accept a single release of the RISC Zero circuits.
    ///
    /// New releases of RISC Zero's zkVM require updating these values. These values can be
    /// obtained by running `cargo run --bin bonsai-ethereum-contracts -F control-id`
    bytes16 public immutable CONTROL_ID_0;
    bytes16 public immutable CONTROL_ID_1;
    bytes32 public immutable BN254_CONTROL_ID;

    /// @notice A short key attached to the seal to select the correct verifier implementation.
    /// @dev A selector is not intended to be collision resistant, in that it is possible to find
    ///      two preimages that result in the same selector. This is acceptable since it's purpose
    ///      to a route a request among a set of trusted verifiers, and to make errors of sending a
    ///      receipt to a mismatching verifiers easier to debug. It is analogous to the ABI
    ///      function selectors.
    bytes4 public immutable SELECTOR;

    /// @notice Identifier for the Groth16 verification key encoded into the base contract.
    /// @dev This value is computed at compile time, and it encoded in multiple levels because the
    /// Solidity optimizer will fail if too many arguments are given to the abi.encode function.
    bytes32 internal constant SELECTOR_GROTH16_VKEY = sha256(
        abi.encodePacked(
            "" /* DO NOT MERGE
            // tag
            sha256("risc0_groth16.VerifyingKey"),
            // down
            abi.encodePacked(alphax, alphay),
            abi.encodePacked(betax1, betax2, betay1, betay2),
            abi.encodePacked(gammax1, gammax2, gammay1, gammay2),
            abi.encodePacked(deltax1, deltax2, deltay1, deltay2),
            abi.encodePacked(IC5x, IC5y),
            abi.encodePacked(IC4x, IC4y),
            abi.encodePacked(IC3x, IC3y),
            abi.encodePacked(IC2x, IC2y),
            abi.encodePacked(IC1x, IC1y),
            abi.encodePacked(IC0x, IC0y)
                 */
        )
    );

    constructor(bytes32 control_root, bytes32 bn254_control_id) {
        (CONTROL_ID_0, CONTROL_ID_1) = splitDigest(control_root);
        BN254_CONTROL_ID = bn254_control_id;

        SELECTOR = bytes4(
            keccak256(
                abi.encode(
                    // Identifier for the proof system.
                    "RISC_ZERO_GROTH16",
                    // Verification key binding the RISC Zero circuits.
                    CONTROL_ID_0,
                    CONTROL_ID_1,
                    BN254_CONTROL_ID,
                    // Groth16 verification key digest.
                    SELECTOR_GROTH16_VKEY
                )
            )
        );
    }

    /// @notice splits a digest into two 128-bit words to use as public signal inputs.
    /// @dev RISC Zero's Circom verifier circuit takes each of two hash digests in two 128-bit
    /// chunks. These values can be derived from the digest by splitting the digest in half and
    /// then reversing the bytes of each.
    function splitDigest(bytes32 digest) internal pure returns (bytes16, bytes16) {
        uint256 reversed = reverseByteOrderUint256(uint256(digest));
        return (bytes16(uint128(reversed)), bytes16(uint128(reversed >> 128)));
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 postStateDigest, bytes32 journalDigest)
        external
        view
        returns (bool)
    {
        return _verifyIntegrity(seal, ReceiptClaimLib.from(imageId, postStateDigest, journalDigest).digest());
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) external view returns (bool) {
        return _verifyIntegrity(receipt.seal, receipt.claimDigest);
    }

    /// @notice internal implementation of verifyIntegrity, factored to avoid copying calldata bytes to memory.
    function _verifyIntegrity(bytes calldata seal, bytes32 claimDigest) internal view returns (bool) {
        (bytes16 claim0, bytes16 claim1) = splitDigest(claimDigest);
        // TODO(victor): Actually check the selector
        Seal memory decodedSeal = abi.decode(seal[4:], (Seal));
        return this.verifyProof(
            decodedSeal.a,
            decodedSeal.b,
            decodedSeal.c,
            [
                uint256(uint128(CONTROL_ID_0)),
                uint256(uint128(CONTROL_ID_1)),
                uint256(uint128(claim0)),
                uint256(uint128(claim1)),
                uint256(BN254_CONTROL_ID)
            ]
        );
    }
}
