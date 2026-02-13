use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreInfo {
    pub validating_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
    pub readonly: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeystoresResponse {
    pub data: Vec<KeystoreInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ImportKeystoresRequest {
    pub keystores: Vec<String>,
    pub passwords: Vec<String>,
    #[serde(default)]
    pub slashing_protection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportKeystoreResult {
    pub status: ImportStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportKeystoresResponse {
    pub data: Vec<ImportKeystoreResult>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteKeystoresRequest {
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteStatus {
    Deleted,
    NotActive,
    NotFound,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteKeystoreResult {
    pub status: DeleteStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteKeystoresResponse {
    pub data: Vec<DeleteKeystoreResult>,
    pub slashing_protection: String,
}
