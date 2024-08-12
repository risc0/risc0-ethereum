// Copyright (c) 2024 RISC Zero, Inc.
//
// All rights reserved.

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
import {L1BlockMock} from "../contracts/test/L1BlockMock.sol";
import {ImageID} from "../contracts/src/ImageID.sol";
import {Counter} from "../contracts/src/Counter.sol";

contract Deploy is Script, RiscZeroCheats {
    function run() external {
        // Read and log the chainID
        uint256 chainId = block.chainid;
        console2.log("You are deploying on ChainID %d", chainId);

        deployAnvil();
    }

    function deployAnvil() internal {
        // load ENV variables first
        uint256 key = vm.envUint("L1_ADMIN_PRIVATE_KEY");
       
        vm.startBroadcast(key);

        IL1CrossDomainMessenger l1CrossDomainMessenger = new L1CrossDomainMessenger();
        console2.log("Deployed L1 IL1CrossDomainMessenger to", address(l1CrossDomainMessenger));

        IRiscZeroVerifier verifier = deployRiscZeroVerifier();

        IL1Block l1Block = new L1BlockMock();
        
        IL2CrossDomainMessenger l2CrossDomainMessenger = new L2CrossDomainMessenger(verifier, ImageID.CROSS_DOMAIN_MESSENGER_ID, address(l1CrossDomainMessenger), l1Block);
        console2.log("Deployed L2 L2CrossDomainMessenger to", address(l2CrossDomainMessenger));

        Counter counter = new Counter(l2CrossDomainMessenger, address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266));
        console2.log("Deployed L1 Counter to", address(counter));

        vm.stopBroadcast();
    }  
}
