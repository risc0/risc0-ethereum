// spdx-license-identifier: apache-2.0
pragma solidity ^0.8.9;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {BaselineGovernor} from "../contracts/BaselineGovernor.sol";
import {RiscZeroGovernor} from "../contracts/RiscZeroGovernor.sol";
import {VoteToken} from "../contracts/VoteToken.sol";
import {IGovernor} from "openzeppelin/contracts/governance/IGovernor.sol";
import {Strings} from "openzeppelin/contracts/utils/Strings.sol";
import {ImageID} from "../contracts/utils/ImageID.sol";
import {RiscZeroMockVerifier, Receipt as VerifierReceipt} from "../contracts/groth16/RiscZeroMockVerifier.sol";
import {IRiscZeroVerifier} from "../contracts/groth16/IRiscZeroVerifier.sol";

contract BenchmarkTestBase is Test {
    BaselineGovernor public baselineGovernor;
    RiscZeroGovernor public riscZeroGovernor;
    VoteToken public voteToken;
    RiscZeroMockVerifier public mockVerifier;

    uint8 public forSupport = 1;
    address[] public accounts;
    uint256 public baselineProposalId;
    uint256 public riscZeroProposalId;
    mapping(address => bytes) public baselineSignatures;
    mapping(address => bytes) public riscZeroSignatures;
    mapping(address => uint256) public keys;
    bytes32 public constant IMAGE_ID = ImageID.FINALIZE_VOTES_ID;
    bytes4 public constant MOCK_SELECTOR = bytes4(uint32(1337));

    function setUp() public virtual {
        voteToken = new VoteToken();
        mockVerifier = new RiscZeroMockVerifier(MOCK_SELECTOR);
        baselineGovernor = new BaselineGovernor(voteToken);
        riscZeroGovernor = new RiscZeroGovernor(
            voteToken,
            IMAGE_ID,
            mockVerifier
        );
    }

    function generateAccounts(uint256 noOfAccounts) public noGasMetering {
        for (uint256 i = 0; i < noOfAccounts; i++) {
            string memory base = string(
                abi.encodePacked("yolo", Strings.toString(i))
            );
            (address tempAddress, uint256 tempPk) = makeAddrAndKey(base);
            accounts.push(tempAddress);
            keys[tempAddress] = tempPk;
        }
    }

    function getSignature(
        uint8 support,
        uint256 proposalId,
        address signer,
        uint256 privateKey
    ) internal noGasMetering returns (bytes memory signature) {
        bytes32 digest = baselineGovernor.voteHash(proposalId, support, signer);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function generateSignatures(
        uint256 proposalId,
        uint256 noOfSignatures,
        bool isBaseline
    ) internal noGasMetering {
        for (uint256 i = 0; i < noOfSignatures; i++) {
            address currentAddress = accounts[i];
            bytes memory signature = getSignature(
                forSupport,
                proposalId,
                currentAddress,
                keys[currentAddress]
            );

            if (isBaseline) {
                baselineSignatures[currentAddress] = signature;
            } else {
                riscZeroSignatures[currentAddress] = signature;
            }
        }
    }

    function getJournal(
        uint256 proposalId,
        uint256 noOfAccounts
    ) internal noGasMetering returns (bytes memory journal) {
        (
            bytes32 finalBallotBoxAccum,
            bytes memory encodedBallots
        ) = hashBallots(noOfAccounts);

        journal = abi.encodePacked(
            proposalId,
            finalBallotBoxAccum,
            encodedBallots
        );
    }

    function getJournalDigest(
        uint256 proposalId,
        uint256 noOfAccounts
    ) internal noGasMetering returns (bytes32 journalDigest) {
        bytes memory journal = getJournal(proposalId, noOfAccounts);
        journalDigest = sha256(journal);
    }

    function hashBallots(
        uint256 noOfAccounts
    ) internal noGasMetering returns (bytes32, bytes memory) {
        bytes memory encodedBallots;
        bytes32 ballotHash = 0x296dc540e823507aa12a2e7be3c9c01672a7d9bb7840214223e8758fdb2986c7;

        // Prepare the journal and receipt for verifyAndFinalizeVotes
        for (uint256 i = 0; i < noOfAccounts; i++) {
            address currentAddress = accounts[i];

            bytes memory encodedVote = abi.encodePacked(
                uint16(0),
                forSupport,
                uint8(0),
                currentAddress
            );

            encodedBallots = bytes.concat(encodedBallots, encodedVote);
            ballotHash = sha256(bytes.concat(ballotHash, encodedVote));
        }

        return (ballotHash, encodedBallots);
    }

    function _createProposalParams()
        internal
        pure
        returns (
            address[] memory,
            uint256[] memory,
            bytes[] memory,
            string memory
        )
    {
        address[] memory targets = new address[](1);
        targets[0] = address(0x4);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSignature("doSomething()");
        string memory description = "Do something";

        return (targets, values, calldatas, description);
    }
}
