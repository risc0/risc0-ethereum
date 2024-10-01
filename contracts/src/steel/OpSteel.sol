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

import {Encoding, Steel} from "./Steel.sol";

abstract contract OpCommitmentValidator {
    /// @notice Address of the OptimismPortal2 contract.
    IOptimismPortal2 public immutable optimismPortal;

    constructor(address _optimismPortal) {
        optimismPortal = IOptimismPortal2(_optimismPortal);
    }

    /// @notice Validates if the Steel commitment.
    /// @return True if the commitment is valid, false otherwise.
    function validateCommitment(Steel.Commitment memory commitment) internal view returns (bool) {
        (uint240 blockID, uint16 version) = Encoding.decodeVersionedID(commitment.blockID);
        if (version == 0x100) {
            return validateDisputeGameCommitment(blockID, commitment.blockDigest);
        } else {
            return Steel.validateCommitment(commitment);
        }
    }

    function validateDisputeGameCommitment(uint256 gameIndex, bytes32 rootClaim) internal view returns (bool) {
        uint32 respectedGameType = optimismPortal.respectedGameType();
        uint64 respectedGameTypeUpdatedAt = optimismPortal.respectedGameTypeUpdatedAt();
        IDisputeGameFactory factory = optimismPortal.disputeGameFactory();

        (uint32 gameType, uint64 createdAt, IDisputeGame game) = factory.gameAtIndex(gameIndex);
        if (gameType != respectedGameType) return false; // wrong type
        if (createdAt < respectedGameTypeUpdatedAt) return false; // old game type
        if (game.status() != DEFENDER_WINS) return false; // not resolved

        return game.rootClaim() == rootClaim;
    }
}

interface IOptimismPortal2 {
    function disputeGameFactory() external view returns (IDisputeGameFactory);
    function respectedGameType() external view returns (uint32);
    function respectedGameTypeUpdatedAt() external view returns (uint64);
}

// https://github.com/ethereum-optimism/optimism/blob/v1.9.2/packages/contracts-bedrock/src/dispute/interfaces/IDisputeGameFactory.sol
interface IDisputeGameFactory {
    function gameCount() external view returns (uint256);
    function gameAtIndex(uint256 index) external view returns (uint32 gameType, uint64 createdAt, IDisputeGame game);
}

// https://github.com/ethereum-optimism/optimism/blob/v1.9.2/packages/contracts-bedrock/src/dispute/interfaces/IDisputeGame.sol
interface IDisputeGame {
    function status() external view returns (uint256);
    function rootClaim() external pure returns (bytes32);
}

uint256 constant DEFENDER_WINS = 2;
