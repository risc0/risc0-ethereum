//! This module provides an implementation of the `deneb` fork
//! of the consensus spec. The primary entrypoints should be one of
//! the "presets" like `mainnet` or `minimal`.
pub mod beacon_block;
pub mod beacon_state;
pub mod blinded_beacon_block;
pub mod blob_sidecar;
pub mod block_processing;
pub mod epoch_processing;
pub mod execution_engine;
pub mod execution_payload;
pub mod fork;
pub mod genesis;
pub mod helpers;
pub mod light_client;
pub mod networking;
pub mod presets;
pub mod spec;

pub use spec::*;

pub use presets::{mainnet, minimal, Preset};
