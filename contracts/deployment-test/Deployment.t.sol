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

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TimelockController} from "openzeppelin/contracts/governance/TimelockController.sol";
import {RiscZeroVerifierRouter} from "../src/RiscZeroVerifierRouter.sol";
import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";
import {ConfigLoader, Deployment, DeploymentLib, VerifierDeployment} from "../src/config/Config.sol";

/// Test designed to be run against a chain with an active deployment of the RISC Zero contracts.
/// Checks that the deployment matches what is recorded in the deployment.toml file.
contract DeploymentTest is Test {
    using DeploymentLib for Deployment;

    Deployment internal deployment;

    TimelockController internal timelockController;
    RiscZeroVerifierRouter internal router;

    function setUp() external {
        string memory configPath = vm.envOr("DEPLOYMENT_CONFIG", string("./deployment.toml"));
        console2.log("Loading deployment config from %s", configPath);
        ConfigLoader.loadDeploymentConfig(configPath).copyTo(deployment);

        // Wrap the control addresses with their respective contract implementations.
        // NOTE: These addresses may be zero, so this does not guarantee contracts are deployed.
        timelockController = TimelockController(payable(deployment.timelockController));
        router = RiscZeroVerifierRouter(deployment.router);
    }

    function testAdminIsSet() external view {
        require(deployment.admin != address(0), "no admin address is set");
    }

    function testTimelockControllerIsDeployed() external view {
        require(address(timelockController) != address(0), "no timelock controller address is set");
        require(
            keccak256(address(timelockController).code) != keccak256(bytes("")), "timelock controller code is empty"
        );
    }

    function testRouterIsDeployed() external view {
        require(address(router) != address(0), "no router address is set");
        require(keccak256(address(router).code) != keccak256(bytes("")), "router code is empty");
    }

    function testTimelockControllerIsConfiguredProperly() external view {
        require(
            timelockController.hasRole(timelockController.PROPOSER_ROLE(), deployment.admin),
            "admin does not have proposer role"
        );
        require(
            timelockController.hasRole(timelockController.EXECUTOR_ROLE(), deployment.admin),
            "admin does not have executor role"
        );
        require(
            timelockController.hasRole(timelockController.CANCELLER_ROLE(), deployment.admin),
            "admin does not have canceller role"
        );
        uint256 deployedDelay = timelockController.getMinDelay();
        console2.log(
            "Min delay on timelock controller is %d; expected value is %d", deployedDelay, deployment.timelockDelay
        );
        require(
            timelockController.getMinDelay() == deployment.timelockDelay,
            "timelock controller min delay is not as expected"
        );
    }

    function testVerifierRouterIsConfiguredProperly() external view {
        require(router.owner() == address(timelockController), "router is not owned by timelock controller");

        for (uint256 i = 0; i < deployment.verifiers.length; i++) {
            VerifierDeployment storage verifierConfig = deployment.verifiers[i];
            console2.log(
                "Checking for deployment to the router of verifier with selector %x and version %s",
                uint256(uint32(verifierConfig.selector)),
                verifierConfig.version
            );
            if (verifierConfig.unroutable) {
                // When a verifier is specified to be unroutable, confirm that it is indeed not added to the router.
                try router.getVerifier(verifierConfig.selector) {
                    revert("expected router.getVerifier to revert");
                } catch (bytes memory err) {
                    // NOTE: We could allot SelectorRemoved as well here.
                    require(
                        keccak256(err)
                            == keccak256(
                                abi.encodeWithSelector(
                                    RiscZeroVerifierRouter.SelectorUnknown.selector, verifierConfig.selector
                                )
                            )
                    );
                    console2.log(
                        "Verifier with selector %x is unroutable, as configured",
                        uint256(uint32(verifierConfig.selector))
                    );
                }
                continue;
            }

            IRiscZeroVerifier verifierImpl = router.getVerifier(verifierConfig.selector);
            require(address(verifierImpl) != address(0), "verifier impl returned the zero address");
            require(keccak256(address(verifierImpl).code) != keccak256(bytes("")), "verifier impl has no deployed code");
            // TODO: When SELECTOR is added to the public verifier interface, also check the verifier has the expected selector.
        }
    }
}
