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

pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";
import {StdCheatsSafe} from "forge-std/StdCheats.sol";
import {CommonBase} from "forge-std/Base.sol";
import {console2} from "forge-std/console2.sol";
import {Strings2} from "murky/differential_testing/test/utils/Strings2.sol";

/// @notice A base contract for Forge cheats useful in testing RISC Zero applications.
abstract contract RiscZeroCheats is CommonBase {
    using Strings2 for bytes;

    /// @notice Returns whether we are using the prover and verifier in dev-mode, or fully verifying.
    function devMode() internal view returns (bool) {
        return vm.envOr("RISC0_DEV_MODE", false);
    }

    /// @notice Returns the journal, post state digest, and Groth16 seal, resulting from running the
    ///     guest with elf_path using input on the Bonsai proving service.
    /// @dev Uses the Bonsai proving service to run the guest and produce an on-chain verifiable
    ///     SNARK attesting to the correctness of the journal output.
    ///     URL and API key for Bonsai should be specified using the BONSAI_API_URL and
    ///     BONSAI_API_KEY environment variables.
    function prove(string memory elf_path, bytes memory input) internal returns (bytes memory, bytes32, bytes memory) {
        string[] memory imageRunnerInput = new string[](10);
        uint256 i = 0;
        imageRunnerInput[i++] = "cargo";
        imageRunnerInput[i++] = "run";
        imageRunnerInput[i++] = "--manifest-path";
        imageRunnerInput[i++] = "lib/risc0-ethereum/ffi/Cargo.toml";
        imageRunnerInput[i++] = "--bin";
        imageRunnerInput[i++] = "risc0-forge-ffi";
        imageRunnerInput[i++] = "-q";
        imageRunnerInput[i++] = "prove";
        imageRunnerInput[i++] = elf_path;
        imageRunnerInput[i++] = input.toHexString();
        return abi.decode(vm.ffi(imageRunnerInput), (bytes, bytes32, bytes));
    }
}
