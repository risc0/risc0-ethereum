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

pragma solidity ^0.8.9;

import {ControlID, RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {RiscZeroVerifierRouter, IRiscZeroVerifier} from "risc0/RiscZeroVerifierRouter.sol";
import {RiscZeroMockVerifier} from "risc0/test/RiscZeroMockVerifier.sol";
import {Steel} from "risc0/steel/Steel.sol";
import {OpCommitmentValidator} from "risc0/steel/OpSteel.sol";

contract Verifier is OpCommitmentValidator {
    address internal constant MAINNET_OPTIMISM_PORTAL_PROXY = address(0xbEb5Fc579115071764c7423A4f12eDde41f106Ed);

    IRiscZeroVerifier public immutable riscZeroVerifier;

    constructor() OpCommitmentValidator(MAINNET_OPTIMISM_PORTAL_PROXY) {
        RiscZeroVerifierRouter router = new RiscZeroVerifierRouter(address(this));

        RiscZeroGroth16Verifier verifier =
            new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        router.addVerifier(verifier.SELECTOR(), verifier);

        RiscZeroMockVerifier mock = new RiscZeroMockVerifier(bytes4(0xFFFFFFFF));
        router.addVerifier(mock.SELECTOR(), mock);

        riscZeroVerifier = router;
    }

    function verify(bytes calldata journal, bytes calldata seal, bytes32 imageID)
        external
        view
        returns (bytes memory payload)
    {
        Steel.Commitment memory commitment = abi.decode(journal[:96], (Steel.Commitment));
        require(validateCommitment(commitment), "Invalid commitment");

        riscZeroVerifier.verify(seal, imageID, sha256(journal));

        return journal[64:];
    }
}
