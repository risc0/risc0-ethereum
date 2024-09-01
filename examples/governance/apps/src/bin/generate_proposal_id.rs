use alloy_primitives::{address, Address, keccak256, U256};
use alloy_sol_types::{sol, SolCall};

sol! {
    function doSomething();
    function propose(address[] targets, uint256[] values, bytes[] calldatas, string description) returns (uint256);
    function hashProposal(address[] targets, uint256[] values, bytes[] calldatas, bytes32 descriptionHash) returns (uint256);
}

fn create_proposal_params() -> (Vec<Address>, Vec<U256>, Vec<Vec<u8>>, String) {
    let targets = vec![address!("0000000000000000000000000000000000000004")];
    let values = vec![U256::from(0)];
    let do_something_call = doSomethingCall {};
    let calldatas = vec![do_something_call.abi_encode()];
    let description = "Do something".to_string();
    
    (targets, values, calldatas, description)
}

fn generate_proposal_id() -> U256 {
    let (targets, values, calldatas, description) = create_proposal_params();
    
    let description_hash = keccak256(description.as_bytes());
    
    let mut encoded = Vec::new();
    hashProposalCall {
        targets,
        values,
        calldatas,
        descriptionHash: description_hash,
    }.abi_encode_raw(&mut encoded);
    
    let hash_encoded = keccak256(&encoded);
    U256::from_be_bytes(*hash_encoded)
}

fn main() {
    let proposal_id = generate_proposal_id();
    println!("Generated Proposal ID: {}", proposal_id);
}
