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

/// @notice Validate an OP L2 block commitment, enabling verification on L1 of Steel queries against L2 state.
/// @dev Application developers should inherit from this contract, and set the `optimismPortal` address
/// to point to the portal contract of the OP L2 that will be the target for Steel queries.
abstract contract OpCommitmentValidator {
    /// @notice Address of the OptimismPortal2 contract.
    IOptimismPortal2 public immutable optimismPortal;

    constructor(address _optimismPortal) {
        optimismPortal = IOptimismPortal2(_optimismPortal);
    }

    /// @notice Validates a Steel commitment.
    /// @param commitment The commitment to validate.
    /// @return True if the commitment is valid, false otherwise.
    function validateCommitment(Steel.Commitment memory commitment) internal view returns (bool) {
        (uint240 blockID, uint16 version) = Encoding.decodeVersionedID(commitment.id);
        if (version == 0x100) {
            return validateDisputeGameCommitment(blockID, commitment.digest);
        } else {
            return Steel.validateCommitment(commitment);
        }
    }

    /// @notice Validates a Dispute Game commitment.
    /// @param gameIndex The index of the game in the DisputeGameFactory.
    /// @param rootClaim The root claim of the dispute game.
    /// @return True if the commitment is valid, false otherwise.
    function validateDisputeGameCommitment(uint256 gameIndex, bytes32 rootClaim) internal view returns (bool) {
        IDisputeGameFactory factory = optimismPortal.disputeGameFactory();
        IAnchorStateRegistry anchorStateRegistry = optimismPortal.anchorStateRegistry();

        // Retrieve game information from the factory.
        (,, IDisputeGame game) = factory.gameAtIndex(gameIndex);

        // Check that the root claim is valid.
        if (!anchorStateRegistry.isGameClaimValid(game)) return false;

        // Finally, verify that the provided root claim matches the game's root claim.
        return game.rootClaim() == rootClaim;
    }
}

// https://github.com/ethereum-optimism/optimism/blob/op-contracts/v4.0.0/packages/contracts-bedrock/interfaces/L1/IOptimismPortal2.sol
interface IOptimismPortal2 {
    function anchorStateRegistry() external view returns (IAnchorStateRegistry);
    function disputeGameFactory() external view returns (IDisputeGameFactory);
}

// https://github.com/ethereum-optimism/optimism/blob/op-contracts/v4.0.0/packages/contracts-bedrock/interfaces/dispute/IAnchorStateRegistry.sol
interface IAnchorStateRegistry {
    function isGameClaimValid(IDisputeGame _game) external view returns (bool);
}

// https://github.com/ethereum-optimism/optimism/blob/op-contracts/v4.0.0/packages/contracts-bedrock/interfaces/dispute/IDisputeGameFactory.sol
interface IDisputeGameFactory {
    function gameCount() external view returns (uint256);
    function gameAtIndex(uint256 _index)
        external
        view
        returns (uint32 gameType_, uint64 timestamp_, IDisputeGame proxy_);
}

// https://github.com/ethereum-optimism/optimism/blob/op-contracts/v4.0.0/packages/contracts-bedrock/interfaces/dispute/IDisputeGame.sol
interface IDisputeGame {
    function rootClaim() external pure returns (bytes32 rootClaim_);
}
