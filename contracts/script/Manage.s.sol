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

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Strings} from "openzeppelin/contracts/utils/Strings.sol";
import {TimelockController} from "openzeppelin/contracts/governance/TimelockController.sol";
import {RiscZeroVerifierRouter} from "../src/RiscZeroVerifierRouter.sol";
import {RiscZeroVerifierEmergencyStop} from "../src/RiscZeroVerifierEmergencyStop.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";
import {IRiscZeroSelectable} from "../src/IRiscZeroSelectable.sol";
import {ControlID, RiscZeroGroth16Verifier} from "../src/groth16/RiscZeroGroth16Verifier.sol";
import {RiscZeroSetVerifier, RiscZeroSetVerifierLib} from "../src/RiscZeroSetVerifier.sol";
import {ConfigLoader, Deployment, DeploymentLib, VerifierDeployment} from "../src/config/Config.sol";

// Default salt used with CREATE2 for deterministic deployment addresses.
// NOTE: It kind of spelled risc0 in 1337.
bytes32 constant CREATE2_SALT = hex"1215c0";

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
    using DeploymentLib for Deployment;

    Deployment internal deployment;
    TimelockController internal _timelockController;
    RiscZeroVerifierRouter internal _verifierRouter;
    RiscZeroVerifierEmergencyStop internal _verifierEstop;
    IRiscZeroVerifier internal _verifier;

    function loadConfig() internal {
        string memory configPath = vm.envOr("DEPLOYMENT_CONFIG", string("./deployment.toml"));
        console2.log("Loading deployment config from %s", configPath);
        ConfigLoader.loadDeploymentConfig(configPath).copyTo(deployment);

        // Wrap the control addresses with their respective contract implementations.
        // NOTE: These addresses may be zero, so this does not guarantee contracts are deployed.
        _timelockController = TimelockController(payable(deployment.timelockController));
        _verifierRouter = RiscZeroVerifierRouter(deployment.router);
    }

    modifier withConfig() {
        loadConfig();
        _;
    }

    /// @notice Returns the address of the deployer, set in the DEPLOYER_ADDRESS env var.
    function deployerAddress() internal returns (address) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (deployerKey != 0) {
            require(vm.addr(deployerKey) == deployer, "DEPLOYER_ADDRESS and DEPLOYER_PRIVATE_KEY are inconsistent");
            vm.rememberKey(deployerKey);
        }
        return deployer;
    }

    /// @notice Returns the address of the contract admin, set in the ADMIN_ADDRESS env var.
    /// @dev This admin address will be set as the owner of the estop contracts, and the proposer
    ///      of for the timelock controller. Note that it is not the "admin" on the timelock.
    function adminAddress() internal view returns (address) {
        return vm.envOr("ADMIN_ADDRESS", deployment.admin);
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
        // Use the address set in the VERIFIER_ESTOP environment variable if it is set.
        _verifierEstop = RiscZeroVerifierEmergencyStop(vm.envOr("VERIFIER_ESTOP", address(0)));
        if (address(_verifierEstop) != address(0)) {
            console2.log("Using RiscZeroVerifierEmergencyStop at address", address(_verifierEstop));
            return _verifierEstop;
        }
        bytes4 selector = bytes4(vm.envBytes("VERIFIER_SELECTOR"));
        for (uint256 i = 0; i < deployment.verifiers.length; i++) {
            if (deployment.verifiers[i].selector == selector) {
                _verifierEstop = RiscZeroVerifierEmergencyStop(deployment.verifiers[i].estop);
                break;
            }
        }
        console2.log(
            "Using RiscZeroVerifierEmergencyStop at address %s and selector %x",
            address(_verifierEstop),
            uint256(bytes32(selector))
        );
        return _verifierEstop;
    }

    /// @notice Determines the contract address of IRiscZeroVerifier from the environment.
    /// @dev Uses the VERIFIER_ESTOP environment variable, and gets the proxied verifier.
    function verifier() internal returns (IRiscZeroVerifier) {
        if (address(_verifier) != address(0)) {
            return _verifier;
        }
        _verifier = verifierEstop().verifier();
        console2.log("Using IRiscZeroVerifier at address", address(_verifier));
        return _verifier;
    }

    /// @notice Determines the contract address of IRiscZeroSelectable from the environment.
    /// @dev Uses the VERIFIER_ESTOP environment variable, and gets the proxied selectable.
    function selectable() internal returns (IRiscZeroSelectable) {
        return IRiscZeroSelectable(address(verifier()));
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract DeployTimelockRouter is RiscZeroManagementScript {
    function run() external withConfig {
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
        _timelockController = new TimelockController{salt: CREATE2_SALT}(minDelay, proposers, executors, admin);
        console2.log("Deployed TimelockController to", address(timelockController()));

        vm.broadcast(deployerAddress());
        _verifierRouter = new RiscZeroVerifierRouter{salt: CREATE2_SALT}(address(timelockController()));
        console2.log("Deployed RiscZeroVerifierRouter to", address(verifierRouter()));
    }
}

/// @notice Script for printing the selector of the RiscZeroSetVerifier.
/// @dev Use the following environment variable to control the script:
///     * SET_BUILDER_IMAGE_ID image ID of the SetBuilder guest
contract SetVerifierSelector is RiscZeroManagementScript {
    function run() external view {
        bytes32 SET_BUILDER_IMAGE_ID = vm.envBytes32("SET_BUILDER_IMAGE_ID");
        console2.log("SET_BUILDER_IMAGE_ID:", Strings.toHexString(uint256(SET_BUILDER_IMAGE_ID)));
        bytes4 selector = RiscZeroSetVerifierLib.selector(SET_BUILDER_IMAGE_ID);
        console2.log("selector:", Strings.toHexString(uint256(uint32(selector))));
    }
}

/// @notice Deployment script for the RISC Zero verifier with Emergency Stop mechanism.
/// @dev Use the following environment variable to control the deployment:
///     * CHAIN_KEY key of the target chain
///     * VERIFIER_ESTOP_OWNER owner of the emergency stop contract
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract DeployEstopGroth16Verifier is RiscZeroManagementScript {
    function run() external withConfig {
        string memory chainKey = vm.envString("CHAIN_KEY");
        console2.log("chainKey:", chainKey);
        address verifierEstopOwner = vm.envOr("VERIFIER_ESTOP_OWNER", adminAddress());
        console2.log("verifierEstopOwner:", verifierEstopOwner);

        // Deploy new contracts
        vm.broadcast(deployerAddress());
        RiscZeroGroth16Verifier groth16Verifier =
            new RiscZeroGroth16Verifier{salt: CREATE2_SALT}(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        _verifier = groth16Verifier;

        vm.broadcast(deployerAddress());
        _verifierEstop = new RiscZeroVerifierEmergencyStop{salt: CREATE2_SALT}(groth16Verifier, verifierEstopOwner);

        // Print in TOML format
        console2.log("");
        console2.log("[[chains.%s.verifiers]]", chainKey);
        console2.log("name = \"RiscZeroGroth16Verifier\"");
        console2.log("version = \"%s\"", groth16Verifier.VERSION());
        console2.log("selector = \"%s\"", Strings.toHexString(uint256(uint32(groth16Verifier.SELECTOR())), 4));
        console2.log("verifier = \"%s\"", address(verifier()));
        console2.log("estop = \"%s\"", address(verifierEstop()));
        console2.log("unroutable = true # remove when added to the router");
    }
}

/// @notice Deployment script for the RISC Zero SetVerifier with Emergency Stop mechanism.
/// @dev Use the following environment variable to control the deployment:
///     * CHAIN_KEY key of the target chain
///     * VERIFIER_ESTOP_OWNER owner of the emergency stop contract
///     * SET_BUILDER_IMAGE_ID image ID of the SetBuilder guest
///     * SET_BUILDER_GUEST_URL URL of the SetBuilder guest
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract DeployEstopSetVerifier is RiscZeroManagementScript {
    function run() external withConfig {
        string memory chainKey = vm.envString("CHAIN_KEY");
        console2.log("chainKey:", chainKey);
        address verifierEstopOwner = vm.envOr("VERIFIER_ESTOP_OWNER", adminAddress());
        console2.log("verifierEstopOwner:", verifierEstopOwner);

        bytes32 SET_BUILDER_IMAGE_ID = vm.envBytes32("SET_BUILDER_IMAGE_ID");
        console2.log("SET_BUILDER_IMAGE_ID:", Strings.toHexString(uint256(SET_BUILDER_IMAGE_ID)));
        string memory SET_BUILDER_GUEST_URL = vm.envString("SET_BUILDER_GUEST_URL");
        console2.log("SET_BUILDER_GUEST_URL:", SET_BUILDER_GUEST_URL);

        // Deploy new contracts
        vm.broadcast(deployerAddress());
        RiscZeroSetVerifier setVerifier =
            new RiscZeroSetVerifier{salt: CREATE2_SALT}(verifierRouter(), SET_BUILDER_IMAGE_ID, SET_BUILDER_GUEST_URL);
        _verifier = setVerifier;

        vm.broadcast(deployerAddress());
        _verifierEstop = new RiscZeroVerifierEmergencyStop{salt: CREATE2_SALT}(_verifier, verifierEstopOwner);

        // Print in TOML format
        console2.log("");
        console2.log("[[chains.%s.verifiers]]", chainKey);
        console2.log("name = \"RiscZeroSetVerifier\"");
        console2.log("version = \"%s\"", setVerifier.VERSION());
        console2.log("selector = \"%s\"", Strings.toHexString(uint256(uint32(setVerifier.SELECTOR())), 4));
        console2.log("verifier = \"%s\"", address(verifier()));
        console2.log("estop = \"%s\"", address(verifierEstop()));
        console2.log("unroutable = true # remove when added to the router");
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract ScheduleAddVerifier is RiscZeroManagementScript {
    function run() external withConfig {
        // Schedule the 'addVerifier()' request
        bytes4 selector = selectable().SELECTOR();
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract FinishAddVerifier is RiscZeroManagementScript {
    function run() external withConfig {
        // Execute the 'addVerifier()' request
        bytes4 selector = selectable().SELECTOR();
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract ScheduleRemoveVerifier is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract FinishRemoveVerifier is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract ScheduleUpdateDelay is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract FinishUpdateDelay is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract CancelOperation is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract ScheduleGrantRole is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract FinishGrantRole is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract ScheduleRevokeRole is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract FinishRevokeRole is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract RenounceRole is RiscZeroManagementScript {
    function run() external withConfig {
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
/// https://book.getfoundry.sh/guides/scripting-with-solidity
contract ActivateEstop is RiscZeroManagementScript {
    function run() external withConfig {
        // Locate contracts
        console2.log("Using RiscZeroVerifierEmergencyStop at address", address(verifierEstop()));

        // Activate the emergency stop
        vm.broadcast(adminAddress());
        verifierEstop().estop();
    }
}
