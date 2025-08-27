// Copyright 2025 RISC Zero, Inc.
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

use std::sync::Arc;

use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{FixedBytes, B256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::Context;
use risc0_ethereum_contracts::IRiscZeroVerifier::{self, IRiscZeroVerifierInstance};
use risc0_ethereum_test_utils_guests::ECHO_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, ProveInfo, ProverOpts, VerifierContext};
use tokio::sync::Mutex;

// Import the Solidity contracts using alloy's sol! macro
// Use the compiled contracts output to allow for deploying the contracts.
// NOTE: This requires running `forge build` before running this test.
// TODO: Work on making this more robust.
sol!(
    #[sol(rpc)]
    MockRiscZeroVerifier,
    "../../out/RiscZeroMockVerifier.sol/RiscZeroMockVerifier.json"
);

sol!(
    #[sol(rpc)]
    RiscZeroGroth16Verifier,
    "../../out/RiscZeroGroth16Verifier.sol/RiscZeroGroth16Verifier.json"
);

#[derive(Clone)]
pub struct TestCtx {
    pub anvil: Arc<Mutex<AnvilInstance>>,
    pub chain_id: u64,
    pub provider: DynProvider,
    pub verifier: IRiscZeroVerifierInstance<DynProvider>,
}

pub async fn text_ctx() -> anyhow::Result<TestCtx> {
    let anvil = Anvil::new().spawn();
    test_ctx_with(Mutex::new(anvil).into(), 0, VerifierContext::default()).await
}

pub async fn test_ctx_with(
    anvil: Arc<Mutex<AnvilInstance>>,
    signer_index: usize,
    verifier_ctx: VerifierContext,
) -> anyhow::Result<TestCtx> {
    let rpc_url = anvil.lock().await.endpoint_url();

    // Create wallet and provider
    let signer: PrivateKeySigner = anvil.lock().await.keys()[signer_index].clone().into();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url)
        .erased();

    // Deploy the verifier contract, using the mock verifier or the real Groth16 verifier depending
    // on the setting of RISC0_DEV_MODE.
    // TODO: Also support deploying the router and set verifier.
    let verifier = if verifier_ctx.dev_mode() {
        let mock_verifier =
            MockRiscZeroVerifier::deploy(provider.clone(), FixedBytes([0xFFu8; 4])).await?;
        println!(
            "MockRiscZeroVerifier deployed at: {:?}",
            mock_verifier.address()
        );
        IRiscZeroVerifier::new(*mock_verifier.address(), provider.clone())
    } else {
        let groth16_verifier_parameters = verifier_ctx
            .groth16_verifier_parameters
            .context("groth16 verifier parameters not provided")?;
        let control_root =
            bytemuck::cast::<_, [u8; 32]>(groth16_verifier_parameters.control_root).into();
        // Byte order in the contract is opposite that of Rust, because the EVM interprets the
        // digest as a big-endian uint256.
        let mut bn254_control_id: B256 =
            bytemuck::cast::<_, [u8; 32]>(groth16_verifier_parameters.bn254_control_id).into();
        bn254_control_id.as_mut_slice().reverse();
        let groth16_verifier =
            RiscZeroGroth16Verifier::deploy(provider.clone(), control_root, bn254_control_id)
                .await?;
        println!(
            "RiscZeroGroth16Verifier deployed at: {:?}",
            groth16_verifier.address()
        );
        IRiscZeroVerifier::new(*groth16_verifier.address(), provider.clone())
    };

    let chain_id = anvil.lock().await.chain_id();
    Ok(TestCtx {
        anvil,
        chain_id,
        provider,
        verifier,
    })
}

/// Prove the echo guest with the given input and [ProverOpts].
pub async fn prove_echo(input: impl AsRef<[u8]>, opts: ProverOpts) -> anyhow::Result<ProveInfo> {
    let input = input.as_ref().to_vec();
    tokio::task::spawn_blocking(move || {
        let env = ExecutorEnv::builder().write_slice(&input).build()?;
        default_prover().prove_with_opts(env, ECHO_ELF, &opts)
    })
    .await
    .context("proving tokio task failed")?
}
