//! This module provides an implementation of the `altair` fork
//! of the consensus spec. The primary entrypoints should be one of
//! the "presets" like `mainnet` or `minimal`.
pub mod beacon_block;
pub mod beacon_state;
pub mod block_processing;
pub mod constants;
pub mod epoch_processing;
pub mod fork;
pub mod genesis;
pub mod helpers;
pub mod light_client;
pub mod networking;
pub mod presets;
pub mod spec;
pub mod sync;
pub mod validator;

pub use spec::*;

pub use presets::{mainnet, minimal, Preset};
