use std::fmt;

// Identifies the fork of the protocol the associated object belongs to.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fork {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
}

impl fmt::Display for Fork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Phase0 => write!(f, "phase0"),
            Self::Altair => write!(f, "altair"),
            Self::Bellatrix => write!(f, "bellatrix"),
            Self::Capella => write!(f, "capella"),
            Self::Deneb => write!(f, "deneb"),
            Self::Electra => write!(f, "electra"),
        }
    }
}
