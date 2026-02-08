#[derive(Debug, thiserror::Error)]
pub enum ValidatorStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("config error: {0}")]
    Config(String),
}
