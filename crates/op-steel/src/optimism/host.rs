use crate::{
    game::host::{DisputeGameIndex, OptimismPortal2},
    optimism::{OpBlockHeader, OpEvmInput},
    DisputeGameCommit,
};
use alloy::{
    network::Ethereum,
    providers::{Provider, ProviderBuilder, ReqwestProvider},
    transports::Transport,
};
use alloy_primitives::{Address, Sealable};
use anyhow::Result;
use op_alloy_network::Optimism;
use risc0_steel::{
    config::ChainSpec,
    host::{
        db::{AlloyDb, ProofDb},
        BlockNumberOrTag, EvmEnvBuilder,
    },
    ComposeInput, EvmEnv, EvmInput,
};
use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use url::Url;

/// Wrapped [EvmEnv] for Optimism.
pub struct OpEvmEnv<D, C> {
    /// Underlying generic environment.
    inner: EvmEnv<D, OpBlockHeader>,
    /// Additional OP-specific commitment.
    commit: C,
}

impl<D, C> OpEvmEnv<D, C> {
    pub fn with_chain_spec(self, chain_spec: &ChainSpec) -> Self {
        let Self { inner, commit } = self;
        Self {
            inner: inner.with_chain_spec(chain_spec),
            commit,
        }
    }
}

impl<D, C> Deref for OpEvmEnv<D, C> {
    type Target = EvmEnv<D, OpBlockHeader>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<D, C> DerefMut for OpEvmEnv<D, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl OpEvmEnv<(), ()> {
    pub fn builder() -> OpEvmEnvBuilder<PreProviderStage, (), ()> {
        OpEvmEnvBuilder {
            inner: EvmEnv::builder(),
            l2_provider: (),
            dispute_game: (),
            stage: PhantomData,
        }
    }
}

type HostOpEvmEnv<T, P2, C> = OpEvmEnv<ProofDb<AlloyDb<T, Optimism, P2>>, C>;

impl<T, P2> HostOpEvmEnv<T, P2, ()>
where
    T: Transport + Clone,
    P2: Provider<T, Optimism>,
{
    pub async fn into_input(self) -> Result<OpEvmInput> {
        let EvmInput::Block(input) = self.inner.into_input().await? else {
            unreachable!()
        };

        Ok(OpEvmInput::Block(input))
    }
}

impl<T, P2> HostOpEvmEnv<T, P2, DisputeGameCommit>
where
    T: Transport + Clone,
    P2: Provider<T, Optimism>,
{
    pub async fn into_input(self) -> Result<OpEvmInput> {
        let EvmInput::Block(input) = self.inner.into_input().await? else {
            unreachable!()
        };

        Ok(OpEvmInput::DisputeGame(ComposeInput::new(
            input,
            self.commit,
        )))
    }
}

/// Builder for building an [OpEvmEnv] on the host.
///
/// The builder can be created using [OpEvmEnv::builder()].
#[derive(Clone, Debug)]
pub struct OpEvmEnvBuilder<Stage, P2, G> {
    /// Underlying generic builder.
    inner: EvmEnvBuilder<P2, OpBlockHeader>,
    /// Clone of the L2 provider.
    l2_provider: P2,
    dispute_game: G,
    stage: PhantomData<Stage>,
}

/// First stage of a [OpEvmEnvBuilder] before a provider is set.
pub struct PreProviderStage;
/// Second stage of a [OpEvmEnvBuilder] after a provider has been set.
pub struct ProviderStage;

#[derive(Clone, Debug)]
pub struct DisputeGame<T, P1> {
    portal: OptimismPortal2<T, P1>,
    index: DisputeGameIndex,
}

// Callable with or without a provider and with or without a game.
impl<Stage, P2, G> OpEvmEnvBuilder<Stage, P2, G> {
    pub fn eip1186_proof_chunk_size(self, chunk_size: usize) -> Self {
        let Self {
            inner,
            l2_provider,
            dispute_game,
            stage,
        } = self;
        Self {
            inner: inner.eip1186_proof_chunk_size(chunk_size),
            l2_provider,
            dispute_game,
            stage,
        }
    }
}

// Callable only without a provider, only without a game.
impl OpEvmEnvBuilder<PreProviderStage, (), ()> {
    /// Sets a fault dispute game that is feasible wrt the L1 `OptimismPortal` contract deployed at
    /// `portal`.
    ///
    /// This is used to create an [OpEvmInput] which can be validated against an L1 fault dispute
    /// game.
    pub fn dispute_game<T, P1>(
        self,
        portal: Address,
        l1_provider: P1,
    ) -> OpEvmEnvBuilder<PreProviderStage, (), DisputeGame<T, P1>>
    where
        T: Transport + Clone,
        P1: Provider<T, Ethereum>,
    {
        let Self {
            inner,
            l2_provider,
            stage,
            ..
        } = self;
        let dispute_game = DisputeGame {
            portal: OptimismPortal2::new(portal, l1_provider),
            index: Default::default(),
        };

        OpEvmEnvBuilder {
            inner,
            l2_provider,
            dispute_game,
            stage,
        }
    }
}

// Callable only without a provider, with or without a game.
impl<G> OpEvmEnvBuilder<PreProviderStage, (), G> {
    /// Sets the L2 Optimism HTTP RPC endpoint that will be used by the [OpEvmEnv].
    pub fn rpc(self, url: Url) -> OpEvmEnvBuilder<ProviderStage, ReqwestProvider<Optimism>, G> {
        self.provider(ProviderBuilder::default().on_http(url))
    }

    /// Sets the L2 Optimism [Provider] that will be used by the [OpEvmEnv].
    pub fn provider<T, P2>(self, provider: P2) -> OpEvmEnvBuilder<ProviderStage, P2, G>
    where
        T: Transport + Clone,
        P2: Provider<T, Optimism> + Clone,
    {
        let inner = EvmEnv::builder().provider(provider.clone());
        let dispute_game = self.dispute_game;
        OpEvmEnvBuilder {
            inner,
            l2_provider: provider,
            dispute_game,
            stage: PhantomData,
        }
    }
}

// Callable only with a provider and only without a game.
impl<P2> OpEvmEnvBuilder<ProviderStage, P2, ()> {
    pub fn block_number(self, number: u64) -> Self {
        let Self {
            inner,
            l2_provider,
            dispute_game,
            stage,
        } = self;
        Self {
            inner: inner.block_number(number),
            l2_provider,
            dispute_game,
            stage,
        }
    }

    pub fn block_number_or_tag(self, block: BlockNumberOrTag) -> Self {
        let Self {
            inner,
            l2_provider,
            dispute_game,
            stage,
        } = self;
        Self {
            inner: inner.block_number_or_tag(block),
            l2_provider,
            dispute_game,
            stage,
        }
    }

    pub async fn build<T>(self) -> Result<HostOpEvmEnv<T, P2, ()>>
    where
        T: Transport + Clone,
        P2: Provider<T, Optimism>,
    {
        Ok(OpEvmEnv {
            inner: self.inner.build().await?,
            commit: (),
        })
    }
}

// Callable with or without a provider and only with a game.
impl<Stage, T, P1, P2> OpEvmEnvBuilder<Stage, P2, DisputeGame<T, P1>> {
    pub fn game_index(mut self, index: DisputeGameIndex) -> Self {
        self.dispute_game.index = index;
        self
    }
}

// Callable only with a provider and with a game.
impl<T, P1, P2> OpEvmEnvBuilder<ProviderStage, P2, DisputeGame<T, P1>>
where
    T: Transport + Clone,
    P1: Provider<T, Ethereum>,
    P2: Provider<T, Optimism>,
{
    pub async fn build(self) -> Result<HostOpEvmEnv<T, P2, DisputeGameCommit>> {
        let game = self
            .dispute_game
            .portal
            .dispute_game(self.dispute_game.index, self.l2_provider)
            .await?;

        let proof = game.output_root_proof;
        let env = self
            .inner
            .block_number(game.l2_block_number)
            .build()
            .await?;
        assert_eq!(proof.latestBlockhash, env.header().hash_slow());

        Ok(OpEvmEnv {
            inner: env,
            commit: DisputeGameCommit::new(game.index.to(), proof),
        })
    }
}
