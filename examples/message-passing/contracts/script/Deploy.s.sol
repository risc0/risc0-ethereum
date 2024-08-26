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

import {Script, console2} from "forge-std/Script.sol";
import {RiscZeroCheats} from "risc0/test/RiscZeroCheats.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ControlID, RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {RiscZeroMockVerifier} from "risc0/test/RiscZeroMockVerifier.sol";
import {IL1CrossDomainMessenger} from "../contracts/src/IL1CrossDomainMessenger.sol";
import {L1CrossDomainMessenger} from "../contracts/src/L1CrossDomainMessenger.sol";
import {IL2CrossDomainMessenger} from "../contracts/src/IL2CrossDomainMessenger.sol";
import {L2CrossDomainMessenger} from "../contracts/src/L2CrossDomainMessenger.sol";
import {IL1Block} from "../contracts/src/IL1Block.sol";
import {ImageID} from "../contracts/src/ImageID.sol";
import {Counter} from "../contracts/src/Counter.sol";

contract Deploy is Script, RiscZeroCheats {
    // In OP the L1Block contract on L2 is always at the same predeployed address
    IL1Block constant L1_BLOCK = IL1Block(0x4200000000000000000000000000000000000015);

    function run() external {
        // load ENV variables first
        uint256 key1 = vm.envUint("L1_ADMIN_PRIVATE_KEY");
        uint256 key2 = vm.envUint("L2_ADMIN_PRIVATE_KEY");
        uint256 l1 = vm.createFork(vm.envString("L1_RPC_URL"));
        uint256 l2 = vm.createFork(vm.envString("L2_RPC_URL"));

        vm.selectFork(l1);
        vm.startBroadcast(key1);

        IL1CrossDomainMessenger l1CrossDomainMessenger = new L1CrossDomainMessenger();
        console2.log("Deployed L1 IL1CrossDomainMessenger to", address(l1CrossDomainMessenger));

        vm.stopBroadcast();

        vm.selectFork(l2);
        vm.startBroadcast(key2);

        IRiscZeroVerifier verifier = deployRiscZeroVerifier();

        IL2CrossDomainMessenger l2CrossDomainMessenger = new L2CrossDomainMessenger(
            verifier, ImageID.CROSS_DOMAIN_MESSENGER_ID, address(l1CrossDomainMessenger), L1_BLOCK
        );
        console2.log("Deployed L2 L2CrossDomainMessenger to", address(l2CrossDomainMessenger));

        Counter counter = new Counter(l2CrossDomainMessenger, address(0x0));
        console2.log("Deployed L1 Counter to", address(counter));

        vm.stopBroadcast();
    }
}
