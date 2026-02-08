#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockServiceError {
    #[error("signer error: {0}")]
    Signer(String),

    #[error("beacon error: {0}")]
    Beacon(String),

    #[error("parse error: {0}")]
    Parse(String),
}
