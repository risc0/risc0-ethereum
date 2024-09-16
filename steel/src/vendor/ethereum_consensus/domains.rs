#[derive(Clone, Copy)]
pub enum DomainType {
    BeaconProposer,              // 0
    BeaconAttester,              // 1
    Randao,                      // 2
    Deposit,                     // 3
    VoluntaryExit,               // 4
    SelectionProof,              // 5
    AggregateAndProof,           // 6
    SyncCommittee,               // 7
    SyncCommitteeSelectionProof, // 8
    ContributionAndProof,        // 9
    BlsToExecutionChange,        // A
    Consolidation,               // B
    ApplicationMask,
    ApplicationBuilder,
}

impl DomainType {
    pub fn as_bytes(&self) -> [u8; 4] {
        match self {
            Self::ApplicationMask => [0, 0, 0, 1],
            Self::ApplicationBuilder => [0, 0, 0, 1],
            _ => {
                let data = *self as u32;
                data.to_le_bytes()
            }
        }
    }
}
