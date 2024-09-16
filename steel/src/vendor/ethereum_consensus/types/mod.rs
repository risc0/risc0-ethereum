//! This module contains high-level types that intend to wrap each of the
//! types defined across all forks.
//!
//! For example, a `BeaconBlock` enum type that contains a variant for each
//! defined fork `phase0`, `altair`, `bellatrix`, `capella`, and onwards.

mod beacon_block;
mod beacon_block_body;
mod beacon_state;
mod blinded_beacon_block;
mod blinded_beacon_block_body;
mod execution_payload;
mod execution_payload_header;
mod presets;
mod signed_beacon_block;
mod signed_blinded_beacon_block;

pub use beacon_block::*;
pub use beacon_block_body::*;
pub use beacon_state::*;
pub use blinded_beacon_block::*;
pub use blinded_beacon_block_body::*;
pub use execution_payload::*;
pub use execution_payload_header::*;
pub use signed_beacon_block::*;
pub use signed_blinded_beacon_block::*;

pub use presets::{mainnet, minimal};
