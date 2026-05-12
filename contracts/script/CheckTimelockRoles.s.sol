// Copyright 2026 RISC Zero, Inc.
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
import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {stdToml} from "forge-std/StdToml.sol";

/// @notice Helper contract that issues a single eth_call via `vm.rpc`.
/// @dev Lives outside the Script so the call can be wrapped with try/catch — Forge
/// rejects external calls to `address(this)` from inside a script.
contract TimelockRoleProbe {
    Vm private constant VM = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function checkAll(string memory rpcUrl, address timelock, address account)
        external
        returns (bool proposer, bool executor, bool canceller)
    {
        proposer = _hasRole(rpcUrl, timelock, keccak256("PROPOSER_ROLE"), account);
        executor = _hasRole(rpcUrl, timelock, keccak256("EXECUTOR_ROLE"), account);
        canceller = _hasRole(rpcUrl, timelock, keccak256("CANCELLER_ROLE"), account);
    }

    function _hasRole(string memory rpcUrl, address timelock, bytes32 role, address account)
        private
        returns (bool)
    {
        bytes memory callData = abi.encodeWithSignature("hasRole(bytes32,address)", role, account);
        string memory params = string.concat(
            '[{"to":"', VM.toString(timelock), '","data":"', VM.toString(callData), '"},"latest"]'
        );
        bytes memory result = VM.rpc(rpcUrl, "eth_call", params);
        return abi.decode(result, (bool));
    }
}

/// @notice Check whether a given account holds the proposer, executor, and canceller roles
/// on the TimelockController deployed on every configured chain.
///
/// Usage:
///   ACCOUNT=0x... forge script --tc CheckTimelockRoles script/CheckTimelockRoles.s.sol
///
/// Optional env vars:
///   NETWORK_TYPE  one of "mainnet" (default), "testnet", or "all"
///
/// RPC URLs are hardcoded below using free public endpoints (Tenderly gateways
/// where available), so no secrets file is required. Roles are queried via direct
/// `eth_call` requests — no chain forks are created.
contract CheckTimelockRoles is Script {
    struct ChainEntry {
        string chainKey;
        string rpcUrl;
        bool isMainnet;
    }

    function _chains() internal pure returns (ChainEntry[] memory chains) {
        chains = new ChainEntry[](16);
        uint256 i = 0;

        // Mainnets.
        chains[i++] = ChainEntry({
            chainKey: "ethereum-mainnet",
            rpcUrl: "https://mainnet.gateway.tenderly.co",
            isMainnet: true
        });
        chains[i++] = ChainEntry({
            chainKey: "arbitrum-mainnet",
            rpcUrl: "https://arbitrum.gateway.tenderly.co",
            isMainnet: true
        });
        chains[i++] = ChainEntry({
            chainKey: "avalanche-mainnet",
            rpcUrl: "https://api.avax.network/ext/bc/C/rpc",
            isMainnet: true
        });
        chains[i++] =
            ChainEntry({chainKey: "base-mainnet", rpcUrl: "https://base.gateway.tenderly.co", isMainnet: true});
        chains[i++] =
            ChainEntry({chainKey: "optimism-mainnet", rpcUrl: "https://optimism.gateway.tenderly.co", isMainnet: true});
        chains[i++] =
            ChainEntry({chainKey: "linea-mainnet", rpcUrl: "https://linea.gateway.tenderly.co", isMainnet: true});
        chains[i++] =
            ChainEntry({chainKey: "polygon-mainnet", rpcUrl: "https://polygon.gateway.tenderly.co", isMainnet: true});
        chains[i++] =
            ChainEntry({chainKey: "polygon-zkevm-mainnet", rpcUrl: "https://zkevm-rpc.com", isMainnet: true});
        chains[i++] = ChainEntry({chainKey: "katana-mainnet", rpcUrl: "https://rpc.katana.network", isMainnet: true});

        // Testnets.
        chains[i++] =
            ChainEntry({chainKey: "ethereum-sepolia", rpcUrl: "https://sepolia.gateway.tenderly.co", isMainnet: false});
        chains[i++] = ChainEntry({
            chainKey: "ethereum-hoodi",
            rpcUrl: "https://ethereum-hoodi-rpc.publicnode.com",
            isMainnet: false
        });
        chains[i++] = ChainEntry({
            chainKey: "arbitrum-sepolia",
            rpcUrl: "https://arbitrum-sepolia.gateway.tenderly.co",
            isMainnet: false
        });
        chains[i++] = ChainEntry({
            chainKey: "avalanche-fuji",
            rpcUrl: "https://api.avax-test.network/ext/bc/C/rpc",
            isMainnet: false
        });
        chains[i++] = ChainEntry({
            chainKey: "base-sepolia",
            rpcUrl: "https://base-sepolia.gateway.tenderly.co",
            isMainnet: false
        });
        chains[i++] = ChainEntry({
            chainKey: "optimism-sepolia",
            rpcUrl: "https://optimism-sepolia.gateway.tenderly.co",
            isMainnet: false
        });
        chains[i++] =
            ChainEntry({chainKey: "linea-sepolia", rpcUrl: "https://rpc.sepolia.linea.build", isMainnet: false});
    }

    function run() external {
        address account = vm.envAddress("ACCOUNT");
        string memory networkType = vm.envOr("NETWORK_TYPE", string("mainnet"));

        bool checkMainnet;
        bool checkTestnet;
        if (_eq(networkType, "mainnet")) {
            checkMainnet = true;
        } else if (_eq(networkType, "testnet")) {
            checkTestnet = true;
        } else if (_eq(networkType, "all")) {
            checkMainnet = true;
            checkTestnet = true;
        } else {
            revert("NETWORK_TYPE must be one of: mainnet, testnet, all");
        }

        string memory deploymentToml = vm.readFile("deployment.toml");
        ChainEntry[] memory chains = _chains();

        TimelockRoleProbe probe = new TimelockRoleProbe();

        console2.log("Checking TimelockController roles");
        console2.log("  account     :", account);
        console2.log("  network type:", networkType);
        console2.log("");

        uint256 chainsChecked;
        uint256 chainsFullyGranted;
        uint256 chainsErrored;

        for (uint256 i = 0; i < chains.length; i++) {
            ChainEntry memory c = chains[i];
            if (c.isMainnet && !checkMainnet) continue;
            if (!c.isMainnet && !checkTestnet) continue;

            address timelock = stdToml.readAddressOr(
                deploymentToml, string.concat(".chains.", c.chainKey, ".timelock-controller"), address(0)
            );
            if (timelock == address(0)) {
                console2.log("[SKIP] %s: no timelock-controller in deployment.toml", c.chainKey);
                continue;
            }

            chainsChecked++;
            try probe.checkAll(c.rpcUrl, timelock, account) returns (bool proposer, bool executor, bool canceller) {
                bool allRoles = proposer && executor && canceller;
                if (allRoles) chainsFullyGranted++;

                console2.log(allRoles ? "[OK]   " : "[MISS] ", c.chainKey);
                console2.log("       timelock :", timelock);
                console2.log("       proposer :", proposer);
                console2.log("       executor :", executor);
                console2.log("       canceller:", canceller);
            } catch {
                chainsErrored++;
                console2.log("[ERR]  %s: failed to query (RPC error?). rpc=%s", c.chainKey, c.rpcUrl);
            }
        }

        console2.log("");
        console2.log("Summary:");
        console2.log("  chains checked       :", chainsChecked);
        console2.log("  fully granted        :", chainsFullyGranted);
        console2.log("  partial / no roles   :", chainsChecked - chainsFullyGranted - chainsErrored);
        console2.log("  rpc errors           :", chainsErrored);
    }

    function _eq(string memory a, string memory b) private pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
