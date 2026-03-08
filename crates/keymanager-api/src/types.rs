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

#[derive(Deserialize)]
pub struct ImportKeystoresRequest {
    pub keystores: Vec<String>,
    pub passwords: Vec<String>,
    #[serde(default)]
    pub slashing_protection: Option<String>,
}

impl std::fmt::Debug for ImportKeystoresRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportKeystoresRequest")
            .field("keystores", &self.keystores)
            .field("passwords", &format_args!("[REDACTED; {}]", self.passwords.len()))
            .field("slashing_protection", &self.slashing_protection)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_keystores_request_debug_redacts_passwords() {
        let req = ImportKeystoresRequest {
            keystores: vec!["ks1".into()],
            passwords: vec!["super_secret_password".into(), "another_secret".into()],
            slashing_protection: None,
        };
        let debug_output = format!("{:?}", req);
        assert!(debug_output.contains("REDACTED"), "Debug output should contain REDACTED");
        assert!(debug_output.contains("[REDACTED; 2]"), "Debug output should show password count");
        assert!(
            !debug_output.contains("super_secret_password"),
            "Debug output must NOT contain actual passwords"
        );
        assert!(
            !debug_output.contains("another_secret"),
            "Debug output must NOT contain actual passwords"
        );
    }
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

// --- Remote key types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteKeyEntry {
    pub pubkey: String,
    pub url: String,
    pub readonly: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRemoteKeysResponse {
    pub data: Vec<RemoteKeyEntry>,
}

#[derive(Debug, Deserialize)]
pub struct RemoteKeyImport {
    pub pubkey: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ImportRemoteKeysRequest {
    pub remote_keys: Vec<RemoteKeyImport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImportRemoteKeyStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportRemoteKeyResult {
    pub status: ImportRemoteKeyStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportRemoteKeysResponse {
    pub data: Vec<ImportRemoteKeyResult>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteRemoteKeysRequest {
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteRemoteKeyStatus {
    Deleted,
    NotFound,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRemoteKeyResult {
    pub status: DeleteRemoteKeyStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRemoteKeysResponse {
    pub data: Vec<DeleteRemoteKeyResult>,
}
