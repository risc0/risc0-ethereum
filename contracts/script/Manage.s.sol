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

/// @notice Compare strings for equality.
function stringEq(string memory a, string memory b) pure returns (bool) {
    return (keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked((b))));
}

/// @notice Return the role code for the given named role
function timelockControllerRole(TimelockController timelockController, string memory roleStr) view returns (bytes32) {
    if (stringEq(roleStr, "proposer")) {
        return timelockController.PROPOSER_ROLE();
    } else if (stringEq(roleStr, "executor")) {
        return timelockController.EXECUTOR_ROLE();
    } else if (stringEq(roleStr, "canceller")) {
        return timelockController.CANCELLER_ROLE();
    } else {
        revert();
    }
}

/// @notice Base contract for the scripts below, providing common context and functions.
contract RiscZeroManagementScript is Script {
    TimelockController internal _timelockController;
    RiscZeroVerifierRouter internal _verifierRouter;
    RiscZeroVerifierEmergencyStop internal _verifierEstop;
    RiscZeroGroth16Verifier internal _verifier;

    /// @notice Returns the address of the deployer, set in the DEPLOYER_PUBLIC_KEY env var.
    function deployerAddress() internal returns (address) {
        address deployer = vm.envAddress("DEPLOYER_PUBLIC_KEY");
        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (deployerKey != 0) {
            require(vm.addr(deployerKey) == deployer, "DEPLOYER_PUBLIC_KEY and DEPLOYER_PRIVATE_KEY are inconsistent");
            vm.rememberKey(deployerKey);
        }
        return deployer;
    }

    /// @notice Returns the address of the contract admin, set in the ADMIN_PUBLIC_KEY env var.
    /// @dev This admin address will be set as the owner of the estop contracts, and the proposer
    ///      of for the timelock controller. Note that it is not the "admin" on the timelock.
    function adminAddress() internal view returns (address) {
        return vm.envAddress("ADMIN_PUBLIC_KEY");
    }

    /// @notice Determines the contract address of TimelockController from the environment.
    /// @dev Uses the TIMELOCK_CONTROLLER environment variable.
    function timelockController() internal returns (TimelockController) {
        if (address(_timelockController) != address(0)) {
            return _timelockController;
        }
        _timelockController = TimelockController(payable(vm.envAddress("TIMELOCK_CONTROLLER")));
        console2.log("Using TimelockController at address", address(_timelockController));
        return _timelockController;
    }

    /// @notice Determines the contract address of RiscZeroVerifierRouter from the environment.
    /// @dev Uses the VERIFIER_ROUTER environment variable.
    function verifierRouter() internal returns (RiscZeroVerifierRouter) {
        if (address(_verifierRouter) != address(0)) {
            return _verifierRouter;
        }
        _verifierRouter = RiscZeroVerifierRouter(vm.envAddress("VERIFIER_ROUTER"));
        console2.log("Using RiscZeroVerifierRouter at address", address(_verifierRouter));
        return _verifierRouter;
    }

    /// @notice Determines the contract address of RiscZeroVerifierRouter from the environment.
    /// @dev Uses the VERIFIER_ESTOP environment variable.
    function verifierEstop() internal returns (RiscZeroVerifierEmergencyStop) {
        if (address(_verifierEstop) != address(0)) {
            return _verifierEstop;
        }
        _verifierEstop = RiscZeroVerifierEmergencyStop(vm.envAddress("VERIFIER_ESTOP"));
        console2.log("Using RiscZeroVerifierEmergencyStop at address", address(_verifierEstop));
        return _verifierEstop;
    }

    /// @notice Determines the contract address of RiscZeroGroth16Verifier from the environment.
    /// @dev Uses the VERIFIER_ESTOP environment variable, and gets the proxied verifier.
    // NOTE: This assumes the verifier is a RiscZeroGroth16Verifier. In the future, this may not
    // be a valid assumption, once we introduce other verifier types.
    function verifier() internal returns (RiscZeroGroth16Verifier) {
        if (address(_verifier) != address(0)) {
            return _verifier;
        }
        _verifier = RiscZeroGroth16Verifier(address(verifierEstop().verifier()));
        console2.log("Using RiscZeroGroth16Verifier at address", address(_verifier));
        return _verifier;
    }

    /// @notice Simulates a call to check if it will succeed, given the current EVM state.
    function simulate(address dest, bytes memory data) internal {
        console2.log("Simulating call to", dest);
        console2.logBytes(data);
        uint256 snapshot = vm.snapshot();
        vm.prank(address(timelockController()));
        (bool success,) = dest.call(data);
        require(success, "simulation of transaction to schedule failed");
        vm.revertTo(snapshot);
        console2.log("Simulation successful");
    }
}

/// @notice Deployment script for the timelocked router.
/// @dev Use the following environment variable to control the deployment:
///     * MIN_DELAY minimum delay in seconds for operations
///     * PROPOSER address of proposer
///     * EXECUTOR address of executor
///     * ADMIN address of admin (optional; leave unset to disable)
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract DeployTimelockRouter is RiscZeroManagementScript {
    function run() external {
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
        // When the admin is unset, the contract is self-administered.
        address admin = vm.envOr("ADMIN", address(0));
        console2.log("admin:", admin);

        // Deploy new contracts
        vm.broadcast(deployerAddress());
        _timelockController = new TimelockController(minDelay, proposers, executors, admin);
        console2.log("Deployed TimelockController to", address(timelockController()));

        vm.broadcast(deployerAddress());
        _verifierRouter = new RiscZeroVerifierRouter(address(timelockController()));
        console2.log("Deployed RiscZeroVerifierRouter to", address(verifierRouter()));
    }
}

/// @notice Deployment script for the RISC Zero verifier with Emergency Stop mechanism.
/// @dev Use the following environment variable to control the deployment:
///     * VERIFIER_ESTOP_OWNER owner of the emergency stop contract
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract DeployEstopVerifier is RiscZeroManagementScript {
    function run() external {
        address verifierEstopOwner = vm.envAddress("VERIFIER_ESTOP_OWNER");
        console2.log("verifierEstopOwner:", verifierEstopOwner);

        // Deploy new contracts
        // TODO: Prints here construct a kind of mangled TOML block that can be copy-pasted into
        // deployment.toml. It should be fixed up to create a proper block.
        vm.broadcast(deployerAddress());
        _verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        console2.log("version = \"", verifier().VERSION(), "\"");
        console2.log("selector = \"");
        console2.logBytes4(verifier().SELECTOR());
        console2.log("verifier = \"", address(verifier()), "\"");

        vm.broadcast(deployerAddress());
        _verifierEstop = new RiscZeroVerifierEmergencyStop(verifier(), verifierEstopOwner);
        console2.log("estop = \"", address(verifierEstop()), "\"");
    }
}

/// @notice Schedule addition of verifier to router.
/// @dev Use the following environment variable to control the deployment:
///     * SCHEDULE_DELAY (optional) minimum delay in seconds for the scheduled action
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///     * VERIFIER_ROUTER contract address of RiscZeroVerifierRouter
///     * VERIFIER_ESTOP contract address of RiscZeroVerifierEmergencyStop
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract ScheduleAddVerifier is RiscZeroManagementScript {
    function run() external {
        // Schedule the 'addVerifier()' request
        bytes4 selector = verifier().SELECTOR();
        console2.log("selector:");
        console2.logBytes4(selector);

        uint256 scheduleDelay = vm.envOr("SCHEDULE_DELAY", timelockController().getMinDelay());
        console2.log("scheduleDelay:", scheduleDelay);

        bytes memory data = abi.encodeCall(verifierRouter().addVerifier, (selector, verifierEstop()));
        address dest = address(verifierRouter());
        simulate(dest, data);

        vm.broadcast(adminAddress());
        timelockController().schedule(dest, 0, data, 0, 0, scheduleDelay);
    }
}

/// @notice Finish addition of verifier to router.
/// @dev Use the following environment variable to control the deployment:
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///     * VERIFIER_ROUTER contract address of RiscZeroVerifierRouter
///     * VERIFIER_ESTOP contract address of RiscZeroVerifierEmergencyStop
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract FinishAddVerifier is RiscZeroManagementScript {
    function run() external {
        // Execute the 'addVerifier()' request
        bytes4 selector = verifier().SELECTOR();
        console2.log("selector:");
        console2.logBytes4(selector);

        bytes memory data = abi.encodeCall(verifierRouter().addVerifier, (selector, verifierEstop()));

        vm.broadcast(adminAddress());
        timelockController().execute(address(verifierRouter()), 0, data, 0, 0);
    }
}

/// @notice Schedule removal of a verifier from the router.
/// @dev Use the following environment variable to control the deployment:
///     * VERIFIER_SELECTOR the selector associated with this verifier
///     * SCHEDULE_DELAY (optional) minimum delay in seconds for the scheduled action
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///     * VERIFIER_ROUTER contract address of RiscZeroVerifierRouter
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract ScheduleRemoveVerifier is RiscZeroManagementScript {
    function run() external {
        bytes4 selector = bytes4(vm.envBytes("VERIFIER_SELECTOR"));
        console2.log("selector:");
        console2.logBytes4(selector);

        // Schedule the 'removeVerifier()' request
        uint256 scheduleDelay = vm.envOr("SCHEDULE_DELAY", timelockController().getMinDelay());
        console2.log("scheduleDelay:", scheduleDelay);

        bytes memory data = abi.encodeCall(verifierRouter().removeVerifier, selector);
        address dest = address(verifierRouter());
        simulate(dest, data);

        vm.broadcast(adminAddress());
        timelockController().schedule(dest, 0, data, 0, 0, scheduleDelay);
    }
}

/// @notice Finish removal of a verifier from the router.
/// @dev Use the following environment variable to control the deployment:
///     * VERIFIER_SELECTOR the selector associated with this verifier
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///     * VERIFIER_ROUTER contract address of RiscZeroVerifierRouter
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract FinishRemoveVerifier is RiscZeroManagementScript {
    function run() external {
        bytes4 selector = bytes4(vm.envBytes("VERIFIER_SELECTOR"));
        console2.log("selector:");
        console2.logBytes4(selector);

        // Execute the 'removeVerifier()' request
        bytes memory data = abi.encodeCall(verifierRouter().removeVerifier, selector);

        vm.broadcast(adminAddress());
        timelockController().execute(address(verifierRouter()), 0, data, 0, 0);
    }
}

/// @notice Schedule an update of the minimum timelock delay.
/// @dev Use the following environment variable to control the deployment:
///     * MIN_DELAY minimum delay in seconds for operations
///     * SCHEDULE_DELAY (optional) minimum delay in seconds for the scheduled action
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract ScheduleUpdateDelay is RiscZeroManagementScript {
    function run() external {
        uint256 minDelay = vm.envUint("MIN_DELAY");
        console2.log("minDelay:", minDelay);

        // Schedule the 'updateDelay()' request
        uint256 scheduleDelay = vm.envOr("SCHEDULE_DELAY", timelockController().getMinDelay());
        console2.log("scheduleDelay:", scheduleDelay);

        bytes memory data = abi.encodeCall(timelockController().updateDelay, minDelay);
        address dest = address(timelockController());
        simulate(dest, data);

        vm.broadcast(adminAddress());
        timelockController().schedule(dest, 0, data, 0, 0, scheduleDelay);
    }
}

/// @notice Finish an update of the minimum timelock delay.
/// @dev Use the following environment variable to control the deployment:
///     * MIN_DELAY minimum delay in seconds for operations
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract FinishUpdateDelay is RiscZeroManagementScript {
    function run() external {
        uint256 minDelay = vm.envUint("MIN_DELAY");
        console2.log("minDelay:", minDelay);

        // Execute the 'updateDelay()' request
        bytes memory data = abi.encodeCall(timelockController().updateDelay, minDelay);

        vm.broadcast(adminAddress());
        timelockController().execute(address(timelockController()), 0, data, 0, 0);
    }
}

// TODO: Add this command to the README.md
/// @notice Cancel a pending operation on the timelock controller
/// @dev Use the following environment variable to control the script:
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///     * OPERATION_ID identifier for the operation to cancel
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract CancelOperation is RiscZeroManagementScript {
    function run() external {
        bytes32 operationId = vm.envBytes32("OPERATION_ID");
        console2.log("operationId:", uint256(operationId));

        // Execute the 'cancel()' request
        vm.broadcast(adminAddress());
        timelockController().cancel(operationId);
    }
}

/// @notice Schedule grant role.
/// @dev Use the following environment variable to control the deployment:
///     * ROLE the role to be granted
///     * ACCOUNT the account to be granted the role
///     * SCHEDULE_DELAY (optional) minimum delay in seconds for the scheduled action
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract ScheduleGrantRole is RiscZeroManagementScript {
    function run() external {
        string memory roleStr = vm.envString("ROLE");
        console2.log("roleStr:", roleStr);

        address account = vm.envAddress("ACCOUNT");
        console2.log("account:", account);

        // Schedule the 'grantRole()' request
        bytes32 role = timelockControllerRole(timelockController(), roleStr);
        console2.log("role: ");
        console2.logBytes32(role);

        uint256 scheduleDelay = vm.envOr("SCHEDULE_DELAY", timelockController().getMinDelay());
        console2.log("scheduleDelay:", scheduleDelay);

        bytes memory data = abi.encodeCall(timelockController().grantRole, (role, account));
        address dest = address(timelockController());
        simulate(dest, data);

        vm.broadcast(adminAddress());
        timelockController().schedule(dest, 0, data, 0, 0, scheduleDelay);
    }
}

/// @notice Finish grant role.
/// @dev Use the following environment variable to control the deployment:
///     * ROLE the role to be granted
///     * ACCOUNT the account to be granted the role
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract FinishGrantRole is RiscZeroManagementScript {
    function run() external {
        string memory roleStr = vm.envString("ROLE");
        console2.log("roleStr:", roleStr);

        address account = vm.envAddress("ACCOUNT");
        console2.log("account:", account);

        // Execute the 'grantRole()' request
        bytes32 role = timelockControllerRole(timelockController(), roleStr);
        console2.log("role: ");
        console2.logBytes32(role);

        bytes memory data = abi.encodeCall(timelockController().grantRole, (role, account));

        vm.broadcast(adminAddress());
        timelockController().execute(address(timelockController()), 0, data, 0, 0);
    }
}

/// @notice Schedule revoke role.
/// @dev Use the following environment variable to control the deployment:
///     * ROLE the role to be revoked
///     * ACCOUNT the account to be revoked of the role
///     * SCHEDULE_DELAY (optional) minimum delay in seconds for the scheduled action
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract ScheduleRevokeRole is RiscZeroManagementScript {
    function run() external {
        string memory roleStr = vm.envString("ROLE");
        console2.log("roleStr:", roleStr);

        address account = vm.envAddress("ACCOUNT");
        console2.log("account:", account);

        // Schedule the 'grantRole()' request
        bytes32 role = timelockControllerRole(timelockController(), roleStr);
        console2.log("role: ");
        console2.logBytes32(role);

        uint256 scheduleDelay = vm.envOr("SCHEDULE_DELAY", timelockController().getMinDelay());
        console2.log("scheduleDelay:", scheduleDelay);

        bytes memory data = abi.encodeCall(timelockController().revokeRole, (role, account));
        address dest = address(timelockController());
        simulate(dest, data);

        vm.broadcast(adminAddress());
        timelockController().schedule(dest, 0, data, 0, 0, scheduleDelay);
    }
}

/// @notice Finish revoke role.
/// @dev Use the following environment variable to control the deployment:
///     * ROLE the role to be revoked
///     * ACCOUNT the account to be revoked of the role
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract FinishRevokeRole is RiscZeroManagementScript {
    function run() external {
        string memory roleStr = vm.envString("ROLE");
        console2.log("roleStr:", roleStr);

        address account = vm.envAddress("ACCOUNT");
        console2.log("account:", account);

        // Execute the 'grantRole()' request
        bytes32 role = timelockControllerRole(timelockController(), roleStr);
        console2.log("role: ");
        console2.logBytes32(role);

        bytes memory data = abi.encodeCall(timelockController().revokeRole, (role, account));

        vm.broadcast(adminAddress());
        timelockController().execute(address(timelockController()), 0, data, 0, 0);
    }
}

/// @notice Renounce role.
/// @dev Use the following environment variable to control the deployment:
///     * RENOUNCE_ADDRESS the address to send the renounce transaction
///     * RENOUNCE_ROLE the role to be renounced
///     * TIMELOCK_CONTROLLER contract address of TimelockController
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract RenounceRole is RiscZeroManagementScript {
    function run() external {
        address renouncer = vm.envAddress("RENOUNCE_ADDRESS");
        string memory roleStr = vm.envString("RENOUNCE_ROLE");
        console2.log("renouncer:", renouncer);
        console2.log("roleStr:", roleStr);

        console2.log("msg.sender:", msg.sender);

        // Renounce the role
        bytes32 role = timelockControllerRole(timelockController(), roleStr);
        console2.log("role: ");
        console2.logBytes32(role);

        vm.broadcast(renouncer);
        timelockController().renounceRole(role, msg.sender);
    }
}

/// @notice Activate an Emergency Stop mechanism.
/// @dev Use the following environment variable to control the deployment:
///     * VERIFIER_ESTOP contract address of RiscZeroVerifierEmergencyStop
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract ActivateEstop is RiscZeroManagementScript {
    function run() external {
        // Locate contracts
        RiscZeroVerifierEmergencyStop verifierEstop = RiscZeroVerifierEmergencyStop(vm.envAddress("VERIFIER_ESTOP"));
        console2.log("Using RiscZeroVerifierEmergencyStop at address", address(verifierEstop));

        // Activate the emergency stop
        vm.broadcast(adminAddress());
        verifierEstop.estop();
    }
}
