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

import {Address} from "openzeppelin/contracts/utils/Address.sol";
import {SafeCast} from "openzeppelin/contracts/utils/math/SafeCast.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {Steel} from "risc0/steel/Steel.sol";
import {IL2CrossDomainMessenger} from "./IL2CrossDomainMessenger.sol";
import {IL1Block} from "./IL1Block.sol";
import {Bookmark} from "./Bookmark.sol";
import {Journal, Message, Digest} from "./Structs.sol";

/// @notice L1Bridging verifier contract for RISC Zero receipts of execution.
contract L2CrossDomainMessenger is IL2CrossDomainMessenger, Bookmark {
    using Address for address;
    using SafeCast for uint256;
    using Digest for Journal;

    /// @notice Value used for the L1 sender storage slot before an actual sender is set. This value is non-zero to
    ///         reduce the gas cost of message passing transactions.
    address internal constant DEFAULT_L1_SENDER = 0x000000000000000000000000000000000000dEaD;

    /// @notice CrossDomainMessenger contract on the other chain.
    address private immutable L1_CROSS_DOMAIN_MESSENGER;

    /// @notice RiscZero verifier contract.
    IRiscZeroVerifier private immutable VERIFIER;

    /// @notice ID of guest.
    bytes32 private immutable IMAGE_ID;

    /// @notice Address of the sender of the currently executing message on the other chain.
    address internal xDomainMsgSender;

    /// @notice Mapping of message hashes to boolean receipt values. A message will only be present in this mapping if
    //          it has successfully been relayed, and can therefore not be relayed again.
    mapping(bytes32 => bool) private relayedMessages;

    constructor(IRiscZeroVerifier verifier, bytes32 imageId, address l1CrossDomainMessenger, IL1Block l1Block)
        Bookmark(l1Block)
    {
        VERIFIER = verifier;
        IMAGE_ID = imageId;
        L1_CROSS_DOMAIN_MESSENGER = l1CrossDomainMessenger;

        xDomainMsgSender = DEFAULT_L1_SENDER;
    }

    function relayMessage(bytes calldata journalData, bytes calldata seal) external {
        VERIFIER.verify(seal, IMAGE_ID, sha256(journalData));

        Journal memory journal = abi.decode(journalData, (Journal));
        require(journal.l1CrossDomainMessenger == L1_CROSS_DOMAIN_MESSENGER, "invalid l1CrossDomainMessenger");
        require(validateCommitment(journal.commitment), "commitment verification failed");

        relayVerifiedMessage(journal.message, journal.messageDigest);
    }

    function xDomainMessageSender() external view returns (address) {
        require(xDomainMsgSender != DEFAULT_L1_SENDER, "L2CrossDomainMessenger: xDomainMsgSender is not set");

        return xDomainMsgSender;
    }

    function validateCommitment(Steel.Commitment memory commitment) internal view returns (bool) {
        return commitment.blockHash == Bookmark.blocks[commitment.blockNumber.toUint64()];
    }

    function relayVerifiedMessage(Message memory message, bytes32 digest) internal {
        require(xDomainMsgSender == DEFAULT_L1_SENDER, "L2CrossDomainMessenger: reentrant call");
        require(!relayedMessages[digest], "L2CrossDomainMessenger: message already relayed");

        xDomainMsgSender = message.sender;
        (bool success, bytes memory returndata) = message.target.call(message.data);
        xDomainMsgSender = DEFAULT_L1_SENDER;

        message.target.verifyCallResultFromTarget(success, returndata);
        relayedMessages[digest] = true;

        emit RelayedMessage(digest);
    }
}
