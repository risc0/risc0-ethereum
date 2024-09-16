//! A fork of the [ethereum-consensus](https://github.com/ralexstokes/ethereum-consensus) crate
//! converted into a module.

pub mod altair;
pub mod bellatrix;
pub mod builder;
pub mod capella;
pub mod clock;
pub mod configs;
pub mod crypto;
pub mod deneb;
pub mod domains;
pub mod electra;
pub mod error;
pub mod execution_engine;
mod fork;
pub mod networks;
pub mod phase0;
pub mod primitives;

pub mod serde;
pub mod signing;
pub mod ssz;
pub mod state_transition;
pub mod types;

pub use error::Error;
pub use fork::Fork;
