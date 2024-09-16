mod context;
mod executor;
mod presets;

pub use context::*;
pub use executor::*;

pub type Result<T> = std::result::Result<T, crate::ethereum_consensus::Error>;

#[derive(Clone, Copy)]
pub enum Validation {
    Enabled,
    Disabled,
}

pub mod mainnet {
    pub use super::presets::mainnet::*;
}

pub mod minimal {
    pub use super::presets::minimal::*;
}
