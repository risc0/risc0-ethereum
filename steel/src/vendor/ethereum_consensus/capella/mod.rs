//! This module provides an implementation of the `capella` fork
//! of the consensus spec. The primary entrypoints should be one of
//! the "presets" like `mainnet` or `minimal`.
pub mod beacon_block;
pub mod beacon_state;
pub mod blinded_beacon_block;
pub mod block_processing;
pub mod bls_to_execution_change;
pub mod epoch_processing;
pub mod execution_payload;
pub mod fork;
pub mod genesis;
pub mod helpers;
pub mod light_client;
pub mod presets;
pub mod spec;
pub mod withdrawal;

pub use spec::*;

pub use presets::{mainnet, minimal, Preset};
