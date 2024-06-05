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

pragma solidity ^0.8.9;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "openzeppelin/contracts/governance/TimelockController.sol";
import {RiscZeroVerifierRouter} from "../src/RiscZeroVerifierRouter.sol";
import {RiscZeroVerifierEmergencyStop} from "../src/RiscZeroVerifierEmergencyStop.sol";
import {IRiscZeroVerifier} from "../src//IRiscZeroVerifier.sol";
import {ControlID, RiscZeroGroth16Verifier} from "../src/groth16/RiscZeroGroth16Verifier.sol";

/// @notice Deployment script for the timelocked router.
/// @dev Use the following environment variable to control the deployment:
///     * MIN_DELAY minimum delay in seconds for operations
///     * PROPOSER address of proposer
///     * EXECUTOR address of executor
///     * ADMIN address of admin (optional; leave unset to disable)
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract DeployTimelockRouter is Script {
    function run() external {
        vm.startBroadcast();

        // initial minimum delay in seconds for operations
        uint256 minDelay = vm.envUint("MIN_DELAY");
        console2.log("minDelay:", minDelay);

        // accounts to be granted proposer and canceller roles
        address[] memory proposers = new address[](1);
        proposers[0] = vm.envAddress("PROPOSER");
        console2.log("proposers:", proposers[0]);

        // accounts to be granted executor role
        address[] memory executors = new address[](1);
        executors[0] = vm.envAddress("EXECUTOR");
        console2.log("executors:", executors[0]);

        // optional account to be granted admin role; disable with zero address
        address admin = vm.envOr("ADMIN", address(0));
        console2.log("admin:", admin);

        // Deploy new contracts
        TimelockController timelockController = new TimelockController(minDelay, proposers, executors, admin);
        console2.log("Deployed TimelockController to", address(timelockController));

        RiscZeroVerifierRouter verifierRouter = new RiscZeroVerifierRouter(address(timelockController));
        console2.log("Deployed RiscZeroVerifierRouter to", address(verifierRouter));

        vm.stopBroadcast();
    }
}

/// @notice Deployment script for the RISC Zero verifier with Emergency Stop mechanism.
/// @dev Use the following environment variable to control the deployment:
///     * SELECTOR the selector associated with this verifier
///     * SCHEDULE_DELAY minimum delay in seconds before the new verifier can be added to the router
///     * VERIFIER_ESTOP_OWNER owner of the emergency stop contract
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///     * VERIFIER_ROUTER contract address of RiscZeroVerifierRouter
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract DeployEstopVerifier is Script {
    function run() external {
        vm.startBroadcast();

        bytes4 selector = bytes4(vm.envBytes("SELECTOR"));
        console2.log("selector:");
        console2.logBytes4(selector);

        uint256 scheduleDelay = vm.envUint("SCHEDULE_DELAY");
        console2.log("scheduleDelay:", scheduleDelay);

        address verifierEstopOwner = vm.envAddress("VERIFIER_ESTOP_OWNER");
        console2.log("verifierEstopOwner:", verifierEstopOwner);

        // Locate contracts
        TimelockController timelockController = TimelockController(payable(vm.envAddress("TIMELOCK_CONTROLLER")));
        console2.log("Using TimelockController at address", address(timelockController));

        RiscZeroVerifierRouter verifierRouter = RiscZeroVerifierRouter(vm.envAddress("VERIFIER_ROUTER"));
        console2.log("Using RiscZeroVerifierRouter at address", address(verifierRouter));

        // Deploy new contracts
        IRiscZeroVerifier verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        console2.log("Deployed IRiscZeroVerifier to", address(verifier));

        RiscZeroVerifierEmergencyStop verifierEstop = new RiscZeroVerifierEmergencyStop(verifier, verifierEstopOwner);
        console2.log("Deployed RiscZeroVerifierEmergencyStop to", address(verifierEstop));

        // Schedule the 'addVerifier()' request
        bytes memory data = abi.encodeCall(verifierRouter.addVerifier, (selector, verifierEstop));

        timelockController.schedule(address(verifierRouter), 0, data, 0, 0, scheduleDelay);

        vm.stopBroadcast();
    }
}

/// @notice Deployment script for the RISC Zero verifier with Emergency Stop mechanism.
/// @dev Use the following environment variable to control the deployment:
///     * SELECTOR the selector associated with this verifier
///     * TIMELOCK_CONTROLLER contract address of TimelockController.
///     * VERIFIER_ROUTER contract address of RiscZeroVerifierRouter
///     * VERIFIER_ESTOP contract address of RiscZeroVerifierEmergencyStop
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract FinishDeployEstopVerifier is Script {
    function run() external {
        vm.startBroadcast();

        bytes4 selector = bytes4(vm.envBytes("SELECTOR"));
        console2.log("selector:");
        console2.logBytes4(selector);

        // Locate contracts
        TimelockController timelockController = TimelockController(payable(vm.envAddress("TIMELOCK_CONTROLLER")));
        console2.log("Using TimelockController at address", address(timelockController));

        RiscZeroVerifierRouter verifierRouter = RiscZeroVerifierRouter(vm.envAddress("VERIFIER_ROUTER"));
        console2.log("Using RiscZeroVerifierRouter at address", address(verifierRouter));

        RiscZeroVerifierEmergencyStop verifierEstop = RiscZeroVerifierEmergencyStop(vm.envAddress("VERIFIER_ESTOP"));
        console2.log("Using RiscZeroVerifierEmergencyStop at address", address(verifierEstop));

        // Execute the 'addVerifier()' request
        bytes memory data = abi.encodeCall(verifierRouter.addVerifier, (selector, verifierEstop));

        timelockController.execute(address(verifierRouter), 0, data, 0, 0);

        vm.stopBroadcast();
    }
}
