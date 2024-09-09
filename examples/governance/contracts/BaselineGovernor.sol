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

import {Governor, IGovernor} from "openzeppelin/contracts/governance/Governor.sol";
import {GovernorSettings} from "openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import {GovernorCountingSimple} from "openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import {GovernorVotes, IVotes} from "openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import {GovernorVotesQuorumFraction} from "openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import {IERC6372} from "openzeppelin/contracts/interfaces/IERC6372.sol";

import {ExtendedGovernorBase} from "./ExtendedGovernorBase.sol";

/// @custom:security-contact security@risczero.com
contract BaselineGovernor is
    ExtendedGovernorBase,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction
{
    constructor(IVotes _token)
        Governor("BaselineGovernor")
        GovernorSettings(300, /* blocks */ 21000, /* blocks */ 0)
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(20)
    {}

    // The following functions are overrides required by Solidity.
    function votingDelay() public view override(Governor, IGovernor, GovernorSettings) returns (uint256) {
        return super.votingDelay();
    }

    function votingPeriod() public view override(Governor, IGovernor, GovernorSettings) returns (uint256) {
        return super.votingPeriod();
    }

    function quorum(uint256 blockNumber)
        public
        view
        override(Governor, IGovernor, GovernorVotesQuorumFraction)
        returns (uint256)
    {
        return super.quorum(blockNumber);
    }

    function proposalThreshold() public view override(Governor, IGovernor, GovernorSettings) returns (uint256) {
        return super.proposalThreshold();
    }

    function clock() public view override(Governor, GovernorVotes, IERC6372) returns (uint48) {
        return super.clock();
    }

    function CLOCK_MODE() public view override(Governor, GovernorVotes, IERC6372) returns (string memory) {
        return super.CLOCK_MODE();
    }
}
