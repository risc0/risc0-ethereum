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

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Pausable} from "openzeppelin/contracts/utils/Pausable.sol";
import {TimelockController} from "openzeppelin/contracts/governance/TimelockController.sol";
import {RiscZeroVerifierRouter} from "../src/RiscZeroVerifierRouter.sol";
import {
    IRiscZeroVerifier, Receipt as RiscZeroReceipt, ReceiptClaim, ReceiptClaimLib
} from "../src/IRiscZeroVerifier.sol";
import {ConfigLoader, Deployment, DeploymentLib, VerifierDeployment} from "../src/config/Config.sol";
import {IRiscZeroSelectable} from "../src/IRiscZeroSelectable.sol";
import {RiscZeroVerifierEmergencyStop} from "../src/RiscZeroVerifierEmergencyStop.sol";
import {TestReceipt as TestReceiptV20} from "../test/TestReceiptV2_0.sol";
import {TestReceipt as TestReceiptV21} from "../test/TestReceiptV2_1.sol";
import {TestReceipt as TestReceiptV22} from "../test/TestReceiptV2_2.sol";
import {TestReceipt as TestReceiptV30} from "../test/TestReceiptV3_0.sol";

// TODO: Check the image ID and ELF URL on the set verifier contract.

library TestReceipts {
    using ReceiptClaimLib for ReceiptClaim;

    // HACK: Get first 4 bytes of a memory bytes vector
    function getFirst4Bytes(bytes memory data) internal pure returns (bytes4) {
        require(data.length >= 4, "Data too short");
        bytes4 result;
        assembly {
            result := mload(add(data, 32))
        }
        return result;
    }

    function getTestReceipt(bytes4 selector) internal pure returns (bool, RiscZeroReceipt memory) {
        if (selector == getFirst4Bytes(TestReceiptV20.SEAL)) {
            bytes32 claimDigest = ReceiptClaimLib.ok(TestReceiptV20.IMAGE_ID, sha256(TestReceiptV20.JOURNAL)).digest();
            return (true, RiscZeroReceipt({seal: TestReceiptV20.SEAL, claimDigest: claimDigest}));
        }
        if (selector == getFirst4Bytes(TestReceiptV21.SEAL)) {
            bytes32 claimDigest = ReceiptClaimLib.ok(TestReceiptV21.IMAGE_ID, sha256(TestReceiptV21.JOURNAL)).digest();
            return (true, RiscZeroReceipt({seal: TestReceiptV21.SEAL, claimDigest: claimDigest}));
        }
        if (selector == getFirst4Bytes(TestReceiptV22.SEAL)) {
            bytes32 claimDigest = ReceiptClaimLib.ok(TestReceiptV22.IMAGE_ID, sha256(TestReceiptV22.JOURNAL)).digest();
            return (true, RiscZeroReceipt({seal: TestReceiptV22.SEAL, claimDigest: claimDigest}));
        }
        if (selector == getFirst4Bytes(TestReceiptV30.SEAL)) {
            bytes32 claimDigest = ReceiptClaimLib.ok(TestReceiptV30.IMAGE_ID, sha256(TestReceiptV30.JOURNAL)).digest();
            return (true, RiscZeroReceipt({seal: TestReceiptV30.SEAL, claimDigest: claimDigest}));
        }
        return (false, RiscZeroReceipt({seal: new bytes(0), claimDigest: bytes32(0)}));
    }
}

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
                    // NOTE: We could allow SelectorRemoved as well here.
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

            IRiscZeroVerifier routedVerifier = router.getVerifier(verifierConfig.selector);
            require(address(routedVerifier) != address(0), "verifier router returned the zero address");
            require(
                address(routedVerifier) == address(verifierConfig.estop), "verifier router returned the wrong address"
            );
        }
    }

    function testVerifierEstopsProperlyConfigured() external view {
        for (uint256 i = 0; i < deployment.verifiers.length; i++) {
            VerifierDeployment storage verifierConfig = deployment.verifiers[i];
            console2.log(
                "Checking for configuration of verifier with selector %x and version %s",
                uint256(uint32(verifierConfig.selector)),
                verifierConfig.version
            );

            RiscZeroVerifierEmergencyStop verifierEstop = RiscZeroVerifierEmergencyStop(verifierConfig.estop);
            require(address(verifierEstop) != address(0), "verifier estop is the zero address");
            require(
                keccak256(address(verifierEstop).code) != keccak256(bytes("")), "verifier estop has no deployed code"
            );
            require(verifierEstop.owner() == deployment.admin, "estop owner is not the admin address");
            if (verifierConfig.stopped) {
                require(verifierEstop.paused(), "verifier estop is not stopped");
            } else {
                require(!verifierEstop.paused(), "verifier estop is stopped");
            }

            IRiscZeroVerifier verifierImpl = verifierEstop.verifier();
            console2.log("verifier implementation is at %s", address(verifierImpl));
            require(address(verifierImpl) != address(0), "verifier impl is the zero address");
            require(address(verifierImpl) == address(verifierConfig.verifier), "verifier impl is the wrong address");
            require(keccak256(address(verifierImpl).code) != keccak256(bytes("")), "verifier impl has no deployed code");

            IRiscZeroSelectable verifierSelectable = IRiscZeroSelectable(address(verifierImpl));
            require(verifierConfig.selector == verifierSelectable.SELECTOR(), "selector mismatch");

            // Ensure that stopped and unroutable verifiers _cannot_ be used to verify a receipt.
            (bool testReceiptExists, RiscZeroReceipt memory testReceipt) =
                TestReceipts.getTestReceipt(verifierConfig.selector);
            if (testReceiptExists) {
                // Check that a direct call to the verifier works. Note that this bypasses the estop.
                console2.log(
                    "Running direct verification of receipt with selector %x", uint256(uint32(verifierConfig.selector))
                );
                verifierImpl.verifyIntegrity(testReceipt);

                // Check that a direct call to the verifier works. Note that this bypasses the estop.
                console2.log(
                    "Running estop verification of receipt with selector %x", uint256(uint32(verifierConfig.selector))
                );
                if (!verifierConfig.stopped) {
                    verifierEstop.verifyIntegrity(testReceipt);
                    console2.log("Verifier with selector %x accepts receipt", uint256(uint32(verifierConfig.selector)));
                } else {
                    try verifierEstop.verifyIntegrity(testReceipt) {
                        revert("expected verifierEstop.verifyIntegrity to revert");
                    } catch (bytes memory err) {
                        require(keccak256(err) == keccak256(abi.encodePacked(Pausable.EnforcedPause.selector)));
                        console2.log(
                            "Verifier with selector %x fails as stopped, as configured",
                            uint256(uint32(verifierConfig.selector))
                        );
                    }
                }
            } else {
                console2.log(
                    "Skipping verification of receipt with selector %x", uint256(uint32(verifierConfig.selector))
                );
            }
        }
    }
}
