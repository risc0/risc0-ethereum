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
import {RiscZeroCheats} from "risc0/test/RiscZeroCheats.sol";
import {Counter} from "../src/Counter.sol";
import {IERC20Metadata} from "openzeppelin-contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ERC20FixedSupply} from "../test/Counter.t.sol";

/// @notice Deployment script for the Counter contract.
/// @dev Use the following environment variable to control the deployment:
///   - ETH_WALLET_PRIVATE_KEY private key of the wallet to be used for deployment.
///   - TOKEN_OWNER to deploy a new ERC 20 token, funding that address with tokens or _alternatively_
///   - TOKEN_CONTRACT to link the Counter to an existing ERC20 token.
///
/// See the Foundry documentation for more information about Solidity scripts.
/// https://book.getfoundry.sh/tutorials/solidity-scripting
contract DeployCounter is Script, RiscZeroCheats {
    function run() external {
        uint256 deployerKey = uint256(vm.envBytes32("ETH_WALLET_PRIVATE_KEY"));

        vm.startBroadcast(deployerKey);

        IERC20Metadata tokenContract = IERC20Metadata(address(0x0));
        try vm.envAddress("TOKEN_CONTRACT") returns (address val) {
            tokenContract = IERC20Metadata(val);
            console2.log("Using ERC20", tokenContract.name(), "at", address(tokenContract));
        } catch {
            // deploy a new ERC20 token if no contract has been specified
            address owner = vm.envAddress("TOKEN_OWNER");
            tokenContract = new ERC20FixedSupply("TOYKEN", "TOY", owner);
            console2.log("Deployed ERC20 TOYKEN to", address(tokenContract));
        }

        IRiscZeroVerifier verifier = deployRiscZeroVerifier();

        Counter counter = new Counter(verifier, address(tokenContract));
        console2.log("Deployed Counter to", address(counter));

        vm.stopBroadcast();
    }
}
