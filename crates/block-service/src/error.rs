use eth_types::Root;

#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockServiceError {
    #[error("signer error: {0}")]
    Signer(String),

    #[error("beacon error: {0}")]
    Beacon(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("slot mismatch: requested {requested}, got {got}")]
    SlotMismatch { requested: u64, got: u64 },

    #[error("builder-only mode: {0}")]
    BuilderOnly(String),

    #[error("proposer_index mismatch: expected {expected}, got {got}")]
    ProposerIndexMismatch { expected: u64, got: u64 },

    #[error(
        "parent_root mismatch: expected 0x{}, got 0x{}",
        hex::encode(expected),
        hex::encode(got)
    )]
    ParentRootMismatch { expected: Root, got: Root },
}
