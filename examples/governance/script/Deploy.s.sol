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

pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IVotes} from "openzeppelin/contracts/governance/utils/IVotes.sol";

import {ControlID, RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {RiscZeroCheats} from "risc0/RiscZeroCheats.sol";
// TODO: Remove:  import {RiscZeroCheats} from "risc0/RiscZeroCheats.sol";

import {BonsaiGovernor} from "../contracts/BonsaiGovernor.sol";
import {VoteToken} from "../contracts/VoteToken.sol";
import {ImageID} from "../contracts/ImageID.sol";

/// @notice deployment script for the Bonsai Governor and it's dependencies.
/// @dev Use the following environment variable to control the deployment:
///     * ETH_WALLET_PRIVATE_KEY private key of the wallet to be used for deployment.
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract Deploy is Script, RiscZeroCheats {
    /// @notice use vm.startBroadcast to begin recording deploy transactions.
    function startBroadcast() internal {
        uint256 deployerKey = uint256(vm.envBytes32("ETH_WALLET_PRIVATE_KEY"));
        vm.startBroadcast(deployerKey);
    }

    function run() external {
        startBroadcast();

        // Deploy an IRiscZeroVerifier contract instance. Relay is stateless and owner-less.
        IRiscZeroVerifier verifier = new RiscZeroGroth16Verifier( ControlID.CONTROL_ID_0, ControlID.CONTROL_ID_1);
        console2.log("Deployed RiscZeroGroth16Verifier to ", address(verifier));

        // Deploy the IVotes token used to grant voting rights.
        // Sender of the transactions will be the owner and controller of the VoteToken.
        IVotes token = new VoteToken();
        console2.log("Deployed VoteToken to ", address(token));

        // Deploy the BonsaiGovernor.
        console2.log( "Image ID for FINALIZE_VOTES is ", vm.toString(ImageID.FINALIZE_VOTES_ID));
        BonsaiGovernor gov = new BonsaiGovernor(token);
        console2.log("Deployed BonsaiGovernor to ", address(gov));

        vm.stopBroadcast();
    }
}
