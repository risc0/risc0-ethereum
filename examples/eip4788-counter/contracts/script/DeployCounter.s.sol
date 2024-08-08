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
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {Counter} from "../src/Counter.sol";

/// @notice Deployment script for the Counter contract.
contract DeployCounter is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("ETH_WALLET_PRIVATE_KEY");
        address verifier = vm.envAddress("RISC_ZERO_VERIFIER_ADDRESS");
        address token = vm.envAddress("TOKEN_CONTRACT");

        vm.startBroadcast(deployerKey);

        Counter counter = new Counter(IRiscZeroVerifier(verifier), token);
        console2.log("Deployed Counter to", address(counter));

        vm.stopBroadcast();
    }
}
