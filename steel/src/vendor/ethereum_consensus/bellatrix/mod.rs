//! This module provides an implementation of the `bellatrix` fork
//! of the consensus spec. The primary entrypoints should be one of
//! the "presets" like `mainnet` or `minimal`.
pub mod beacon_block;
pub mod beacon_state;
pub mod blinded_beacon_block;
pub mod block_processing;
pub mod epoch_processing;
pub mod execution_payload;
pub mod fork;
pub mod fork_choice;
pub mod genesis;
pub mod helpers;
pub mod networking;
pub mod presets;
pub mod spec;
pub mod state_transition;

pub use spec::*;

pub use presets::{mainnet, minimal, Preset};
