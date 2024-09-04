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

use alloy_primitives::{address, hex, keccak256, B256, U256};
use alloy_sol_types::{sol, SolValue};
use alloy::signers::{local::PrivateKeySigner, Signature, Signer};

use anyhow::{Result, Context};
use clap::{Parser, ValueEnum};

sol! {
    function voteHash(uint256 proposalId, uint8 support, address voter) returns (bytes32);
    struct VoteDigest {
        bytes32 BALLOT_TYPEHASH;
        uint256 proposalId;
        uint8 support;
        address voter;
        uint256 nonce;
    }
    struct DomainSeparator {
        bytes32 typeHash;
        bytes32 hashedName;
        bytes32 hashedVersion;
        uint256 chainId;
        address verifyingContract;
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    nonce: U256,

    #[clap(long)]
    proposal_id: U256,

    #[clap(short, long, value_enum)]
    support: Support,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Support {
    Against,
    For,
    Abstain
}

impl Support {
    fn as_u8(&self) -> u8 {
        match self {
            Support::Against => 0,
            Support::For => 1,
            Support::Abstain => 2,
        }
    }
}

async fn generate_vote_data(nonce: U256, proposal_id: U256, support: Support) -> Result<()> {
    let voter_address = address!("4DAfB91f6682136032C004768837e60Bc099E52C");
    let ballot_typehash =
        keccak256("Ballot(uint256 proposalId,uint8 support,address voter,uint256 nonce)");
    let vote_support = support.as_u8();
    let vote_digest = VoteDigest {
        BALLOT_TYPEHASH: ballot_typehash,
        proposalId: proposal_id,
        support: vote_support,
        voter: voter_address,
        nonce,
    };

    let domain_separator = build_domain_separator();
    let struct_hash = keccak256(vote_digest.abi_encode());
    
    let digest = to_typed_data_hash(domain_separator, struct_hash);
    let signer: PrivateKeySigner = make_signer_from_name("voter");
    
    // let signature = signer.sign_message(&digest[..]).await.context("Failed to sign message")?;
    let signature = signer.sign_hash(&digest).await.context("Failed to sign message")?;
    
    encode_vote_data(vote_support, digest, signature);
    
    Ok(())
}

fn encode_vote_data(vote_support: u8, digest: B256, signature: Signature) -> [u8; 100] {
    let v = signature.v();
    let r = signature.r();
    let s = signature.s();
    
    let mut vote_data = [0u8; 2 + 1 + 1 + 32 + 32 + 32];
    
    // first two bytes are uint16(1)
    vote_data[0] = 0;
    vote_data[1] = 1;
    
    // support byte
    vote_data[2] = vote_support;
   
    // v parity byte
    vote_data[3] = v.y_parity_byte_non_eip155().unwrap();
    
    vote_data[4..36].copy_from_slice(&r.to_be_bytes_vec());
    vote_data[36..68].copy_from_slice(&s.to_be_bytes_vec());
    vote_data[68..100].copy_from_slice(&digest.as_slice());
    
    println!(); 
    println!("Vote Data: {}", hex::encode(&vote_data));
    
    return vote_data;
}

fn build_domain_separator() -> B256 {
    let domain_separator_struct = DomainSeparator {
        typeHash: keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        hashedName: keccak256("RiscZeroGovernor"),
        hashedVersion: keccak256("1"),
        chainId: U256::from(31337),
        
        // risc zero governor address in anvil deployment
        verifyingContract: address!("5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9"),
    };
     
    return keccak256(domain_separator_struct.abi_encode());
}

fn to_typed_data_hash(domain_separator: B256, struct_hash: B256) -> B256 {
    let mut digest_input = [0u8; 2 + 32 + 32];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&domain_separator.as_slice());
    digest_input[34..66].copy_from_slice(&struct_hash.as_slice());
    
    return keccak256(digest_input);
}

fn make_signer_from_name(name: &str) -> PrivateKeySigner {
    let private_key = keccak256(name.as_bytes());
    let private_key_string = private_key.to_string();
    let signer: PrivateKeySigner = private_key_string.parse().expect("Failed to parse private key");
    
    let address = signer.address();
    println!("Signer Address: {}", address);
    // assumes local hardhat/foundry chain
    return signer.with_chain_id(Some(31337));
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    generate_vote_data(args.nonce, args.proposal_id, args.support).await?;
    Ok(())
}
