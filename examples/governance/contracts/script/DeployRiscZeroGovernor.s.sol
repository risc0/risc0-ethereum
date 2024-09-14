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

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {RiscZeroCheats} from "risc0/test/RiscZeroCheats.sol";
import {ImageID} from "../src/ImageID.sol";
import {ControlID, RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {IVotes} from "openzeppelin/contracts/governance/utils/IVotes.sol";

import {RiscZeroGovernor} from "../src/RiscZeroGovernor.sol";
import {VoteToken} from "../src/VoteToken.sol";

/// @notice deployment script for RiscZeroGovernor and it's dependencies.
/// @dev Use the following environment variables to control the deployment:
///     * DEPLOYER_ADDRESS address of the wallet to be used for sending deploy transactions.
///         Must be unlocked on the RPC provider node.
///     * DEPLOYER_PRIVATE_KEY private key of the wallet to be used for deployment.
///         Alternative to using DEPLOYER_ADDRESS.
///     * DEPLOY_VERFIER_ADDRESS address of a predeployed IRiscZeroVerifier contract.
///         If not specified and also DEPLOY_BONSAI_RELAY_ADDRESS is not specified,
///         a new RiscZeroGroth16Verifier will be deployed.
///     * DEPLOY_VOTE_TOKEN_ADDRESS address of a predeployed IVotes contract.
///         If not specified, a new VoteToken contract will be deployed.
///         Note that the deployer address will be the owner of the VoteToken contract.
contract DeployRiscZeroGovernor is Script, RiscZeroCheats {
    /// @notice use vm.startBroadcast to begin recording deploy transactions.
    function startBroadcast() internal {
        address deployerAddr = vm.envOr("DEPLOYER_ADDRESS", address(0));
        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));

        if (deployerAddr != address(0) && deployerKey != uint256(0)) {
            revert("only one of DEPLOYER_ADDRESS or DEPLOYER_PRIVATE_KEY should be set");
        }
        if (deployerAddr != address(0)) {
            vm.startBroadcast(deployerAddr);
        } else if (deployerKey != uint256(0)) {
            vm.startBroadcast(deployerKey);
        } else if (block.chainid == 31337) {
            // On an Anvil local testnet, use the first private key by default.
            deployerKey = uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80);
            vm.startBroadcast(deployerKey);
        } else {
            revert("specify a deployer with either DEPLOYER_ADDRESS or DEPLOYER_PRIVATE_KEY");
        }
    }

    function run() external {
        startBroadcast();

        // Deploy an IRiscZeroVerifier contract.
        IRiscZeroVerifier verifier;
        address verifierAddr = vm.envOr("DEPLOY_VERFIER_ADDRESS", address(0));
        if (verifierAddr != address(0)) {
            console2.log("Using IRiscZeroVerifier at ", address(verifierAddr));
            verifier = IRiscZeroVerifier(verifierAddr);
        } else {
            verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
            console2.log("Deployed RiscZeroGroth16Verifier to ", address(verifier));
        }
        // Deploy the IVotes token used to grant voting rights.
        IVotes token;
        address tokenAddr = vm.envOr("DEPLOY_VOTE_TOKEN_ADDRESS", address(0));
        if (tokenAddr != address(0)) {
            console2.log("Using IVotes at ", address(tokenAddr));
            token = IVotes(tokenAddr);
        } else {
            // Sender of the transactions will be the owner and controller of the VoteToken.
            token = new VoteToken();
            console2.log("Deployed VoteToken to ", address(token));
        }

        // Deploy the RiscZeroGovernor.
        // importing ImageID from auto-generated ImageID.sol
        bytes32 imageId = ImageID.FINALIZE_VOTES_ID;
        RiscZeroGovernor gov = new RiscZeroGovernor(token, imageId, verifier);
        console2.log("Deployed RiscZeroGovernor to ", address(gov));

        vm.stopBroadcast();
    }
}
