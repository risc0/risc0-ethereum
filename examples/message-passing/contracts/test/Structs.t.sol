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

import "forge-std/Test.sol";
import {Message, Digest} from "../src/Structs.sol";

contract DigestTest is Test {
    using Digest for Message;

    function testMessageStructHash() public pure {
        Message memory message = Message({
            target: 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9,
            sender: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,
            data: hex"d09de08a",
            nonce: 0
        });

        assertEq(message.digest(), 0x0c6548312532ea5e926eaf99520bb0bd62d4ca58ad70c07d31256331ba7dd4cb);
    }
}
