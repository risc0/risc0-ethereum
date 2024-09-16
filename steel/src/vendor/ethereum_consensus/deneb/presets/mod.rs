pub mod mainnet;
pub mod minimal;

pub struct Preset {
    pub field_elements_per_blob: usize,
    pub max_blob_commitments_per_block: usize,
    pub max_blobs_per_block: usize,
}

pub const TRUSTED_SETUP_JSON: &str = include_str!("trusted_setup.json");
