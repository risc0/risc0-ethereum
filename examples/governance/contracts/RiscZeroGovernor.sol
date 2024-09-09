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
import {GovernorVotes, IVotes} from "openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import {GovernorVotesQuorumFraction} from "openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";

import {RiscZeroGovernorCounting} from "./RiscZeroGovernorCounting.sol";
import {ExtendedGovernorBase} from "./ExtendedGovernorBase.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

import {IERC6372} from "openzeppelin/contracts/interfaces/IERC6372.sol";

/// @custom:security-contact security@risczero.com
contract RiscZeroGovernor is
    ExtendedGovernorBase,
    GovernorSettings,
    RiscZeroGovernorCounting,
    GovernorVotes,
    GovernorVotesQuorumFraction
{
    /// @notice RISC Zero zkVM image ID for the vote finalization program.
    bytes32 public immutable imageId;
    IRiscZeroVerifier public immutable verifier;

    constructor(IVotes token_, bytes32 imageId_, IRiscZeroVerifier verifier_)
        Governor("RiscZeroGovernor")
        GovernorSettings(300, /* blocks */ 21000, /* blocks */ 0)
        GovernorVotes(token_)
        GovernorVotesQuorumFraction(20)
    {
        imageId = imageId_;
        verifier = verifier_;
    }

    /**
     * @notice Calculate the current state of the proposal.
     * @dev See {IGovernor-state}.
     */
    function state(uint256 proposalId) public view override(IGovernor, Governor) returns (ProposalState) {
        ProposalState superState = super.state(proposalId);

        // If the votes have not been finalized, by proving the off-chain verified list of validated
        // ballots, then keep the proposal status as active. IGovernor does not provide a state to
        // indicate that voting has ended, but the result is unknown.
        if (superState == ProposalState.Defeated && !_proposalVotesFinalized(proposalId)) {
            return ProposalState.Active;
        }
        return superState;
    }

    /**
     * @dev See {IGovernor-castVote}.
     *      Does not return the voter's balance, since balance lookups are deferred.
     */
    function castVote(uint256 proposalId, uint8 support) public override(Governor, IGovernor) returns (uint256) {
        address voter = _msgSender();
        _commitVote(proposalId, support, voter);
        emit VoteCast(voter, proposalId, support, 0, "");
        return 0;
    }

    /**
     * @dev See {IGovernor-castVoteWithReason}.
     *      Does not return the voter's balance, since balance lookups are deferred.
     */
    function castVoteWithReason(uint256 proposalId, uint8 support, string calldata reason)
        public
        override(Governor, IGovernor)
        returns (uint256)
    {
        address voter = _msgSender();
        _commitVote(proposalId, support, voter);
        emit VoteCast(voter, proposalId, support, 0, reason);
        return 0;
    }

    /*
     * @dev See {IGovernor-castVoteWithReasonAndParams}.
     *      Does not return the voter's balance, since balance lookups are deferred.
     */
    function castVoteWithReasonAndParams(uint256 proposalId, uint8 support, string calldata reason, bytes memory params)
        public
        override(Governor, IGovernor)
        returns (uint256)
    {
        require(params.length == 0, "RiscZeroGovernor: params are not supported");

        address voter = _msgSender();
        _commitVote(proposalId, support, voter);
        emit VoteCast(voter, proposalId, support, 0, reason);
        return 0;
    }

    /**
     * @dev See {IGovernor-castVoteBySig}.
     *      Does not return the voter's balance, since balance lookups are deferred.
     *      Also does not log a VoteCast event because it cannot be determined yet if this is a valid vote.
     */
    function castVoteBySig(uint256 proposalId, uint8 support, address voter, bytes memory signature)
        public
        override(Governor, IGovernor)
        returns (uint256)
    {
        bytes32 digest = voteHash(proposalId, support, voter);

        _commitVoteBySig(proposalId, support, signature, digest);
        return 0;
    }

    /**
     * @dev See {IGovernor-castVoteWithReasonAndParamsBySig}.
     *      Does not return the voter's balance, since balance lookups are deferred.
     *      Also does not log a VoteCast event because it cannot be determined yet if this is a valid vote.
     */
    function castVoteWithReasonAndParamsBySig(
        uint256 proposalId,
        uint8 support,
        string calldata reason,
        bytes memory params,
        bytes memory signature
    ) public returns (uint256) {
        require(params.length == 0, "RiscZeroGovernor: params are not supported");

        bytes32 digest = voteHashWithReasonAndParamsBySig(proposalId, support, reason, params);
        _commitVoteBySig(proposalId, support, signature, digest);
        return 0;
    }

    /// @notice verify the proof of the `finalize_votes` guest program and finalize the vote count.
    /// `seal`: the seal is a zk-STARK and generated by the prover.
    /// `journal`: the public outputs of the computation.
    function verifyAndFinalizeVotes(bytes calldata seal, bytes calldata journal) public {
        // verify the proof
        verifier.verify(seal, imageId, sha256(journal));

        // decode the journal
        uint256 proposalId = uint256(bytes32(journal[0:32]));
        bytes32 ballotHash = bytes32(journal[32:64]);
        bytes calldata votingData = journal[64:];

        _finalizeVotes(proposalId, ballotHash, votingData);
    }

    function _castVote(uint256, address, uint8, string memory, bytes memory) internal pure override returns (uint256) {
        revert("_castVote is not supported");
    }

    // The following functions are overrides required by Solidity.

    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) public override(IGovernor, Governor, RiscZeroGovernorCounting) returns (uint256) {
        return super.propose(targets, values, calldatas, description);
    }

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
