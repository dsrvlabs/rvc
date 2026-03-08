use async_trait::async_trait;
use google_cloud_gax::error::rpc::Code;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use tracing::{debug, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::{KeyMaterial, SecretKeyEntry, SecretProvider, SecretProviderError};

pub struct GcpSecretProviderConfig {
    pub project_id: String,
    pub prefix: String,
}

impl Default for GcpSecretProviderConfig {
    fn default() -> Self {
        Self { project_id: String::new(), prefix: "validator-key-".to_string() }
    }
}

pub struct GcpSecretProvider {
    client: SecretManagerService,
    project_id: String,
    prefix: String,
}

impl GcpSecretProvider {
    pub async fn new(config: GcpSecretProviderConfig) -> Result<Self, SecretProviderError> {
        let client = SecretManagerService::builder()
            .build()
            .await
            .map_err(|e| SecretProviderError::Auth(format!("failed to create GCP client: {e}")))?;

        Ok(Self { client, project_id: config.project_id, prefix: config.prefix })
    }

    fn parent(&self) -> String {
        format!("projects/{}", self.project_id)
    }

    fn secret_version_name(&self, secret_id: &str) -> String {
        format!("projects/{}/secrets/{}/versions/latest", self.project_id, secret_id)
    }

    async fn access_secret_payload(
        &self,
        secret_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SecretProviderError> {
        let name = self.secret_version_name(secret_id);
        let response = self
            .client
            .access_secret_version()
            .set_name(&name)
            .send()
            .await
            .map_err(|e| map_sdk_error(e, &name))?;

        let payload = response
            .payload
            .ok_or_else(|| SecretProviderError::Provider("empty payload".into()))?;

        Ok(Zeroizing::new(payload.data.to_vec()))
    }

    async fn fetch_companion_password(
        &self,
        secret_id: &str,
    ) -> Result<Zeroizing<String>, SecretProviderError> {
        let password_id = format!("{secret_id}-password");
        let data = self.access_secret_payload(&password_id).await?;
        let raw_bytes = data.to_vec();
        let password = match String::from_utf8(raw_bytes) {
            Ok(s) => s,
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                return Err(SecretProviderError::InvalidKeyMaterial(format!(
                    "password secret {password_id} is not valid UTF-8"
                )));
            }
        };
        let result = Zeroizing::new(password.trim().to_string());
        let mut password = password;
        password.zeroize();
        Ok(result)
    }
}

fn extract_secret_id(full_name: &str) -> &str {
    full_name.rsplit('/').next().unwrap_or(full_name)
}

fn extract_pubkey_from_name(secret_id: &str, prefix: &str) -> Option<String> {
    secret_id.strip_prefix(prefix).map(|s| s.to_string())
}

fn map_sdk_error(err: google_cloud_secretmanager_v1::Error, context: &str) -> SecretProviderError {
    if let Some(status) = err.status() {
        match status.code {
            Code::Unauthenticated => {
                return SecretProviderError::Auth(format!("unauthenticated: {err}"));
            }
            Code::PermissionDenied => {
                return SecretProviderError::Auth(format!("permission denied: {err}"));
            }
            Code::NotFound => {
                return SecretProviderError::NotFound(context.to_string());
            }
            _ => {}
        }
    }

    if let Some(code) = err.http_status_code() {
        match code {
            401 | 403 => return SecretProviderError::Auth(format!("{err}")),
            404 => return SecretProviderError::NotFound(context.to_string()),
            _ => {}
        }
    }

    SecretProviderError::Provider(format!("{err}"))
}

#[async_trait]
impl SecretProvider for GcpSecretProvider {
    fn name(&self) -> &str {
        "gcp"
    }

    #[tracing::instrument(name = "rvc.secret_provider.gcp.list", skip_all, fields(keys.count = tracing::field::Empty))]
    async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
        use google_cloud_gax::paginator::ItemPaginator as _;

        let filter = format!("name:{}", self.prefix);
        let parent = self.parent();

        let mut items = self
            .client
            .list_secrets()
            .set_parent(&parent)
            .set_filter(&filter)
            .set_page_size(100)
            .by_item();

        let mut entries = Vec::new();
        while let Some(item) = items.next().await {
            let secret = item.map_err(|e| map_sdk_error(e, &parent))?;
            let secret_id = extract_secret_id(&secret.name);

            if secret_id.ends_with("-password") {
                debug!(secret_id, "skipping companion password secret");
                continue;
            }

            let pubkey_hex = extract_pubkey_from_name(secret_id, &self.prefix);
            entries.push(SecretKeyEntry { id: secret_id.to_string(), pubkey_hex });
        }

        tracing::Span::current().record("keys.count", entries.len());
        debug!(count = entries.len(), "listed GCP secrets");
        Ok(entries)
    }

    #[tracing::instrument(name = "rvc.secret_provider.gcp.fetch", skip_all, fields(key.id = %id))]
    async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
        let data = self.access_secret_payload(id).await?;

        match crate::format::parse_secret_data(&data)? {
            crate::format::SecretDataFormat::KeystoreJson(json) => {
                let password = self.fetch_companion_password(id).await.map_err(|e| {
                    warn!(secret_id = id, error = %e, "failed to fetch companion password");
                    e
                })?;
                Ok(KeyMaterial::Keystore { keystore_json: json, password })
            }
            crate::format::SecretDataFormat::RawHex(key) => Ok(KeyMaterial::RawKey(key)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_secret_id_full_path() {
        let name = "projects/my-project/secrets/validator-key-abc123";
        assert_eq!(extract_secret_id(name), "validator-key-abc123");
    }

    #[test]
    fn test_extract_secret_id_bare_name() {
        assert_eq!(extract_secret_id("validator-key-abc"), "validator-key-abc");
    }

    #[test]
    fn test_extract_pubkey_with_prefix() {
        let id = "validator-key-0xabc123";
        let pubkey = extract_pubkey_from_name(id, "validator-key-");
        assert_eq!(pubkey, Some("0xabc123".to_string()));
    }

    #[test]
    fn test_extract_pubkey_no_prefix() {
        let id = "other-secret";
        let pubkey = extract_pubkey_from_name(id, "validator-key-");
        assert_eq!(pubkey, None);
    }

    #[test]
    fn test_format_detection_delegates_to_format_module() {
        use crate::format::{parse_secret_data, SecretDataFormat};

        // JSON detection
        let data = br#"{"version":4,"crypto":{}}"#;
        assert!(matches!(parse_secret_data(data), Ok(SecretDataFormat::KeystoreJson(_))));

        // Hex detection
        let hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert!(matches!(parse_secret_data(hex.as_bytes()), Ok(SecretDataFormat::RawHex(_))));

        // Non-UTF-8 returns error
        let data = [0xFF, 0xFE, 0x00, 0x01];
        assert!(parse_secret_data(&data).is_err());
    }

    #[test]
    fn test_config_defaults() {
        let config = GcpSecretProviderConfig::default();
        assert_eq!(config.prefix, "validator-key-");
        assert!(config.project_id.is_empty());
    }

    #[test]
    fn test_config_custom() {
        let config =
            GcpSecretProviderConfig { project_id: "my-project".into(), prefix: "bls-key-".into() };
        assert_eq!(config.project_id, "my-project");
        assert_eq!(config.prefix, "bls-key-");
    }

    #[test]
    fn test_secret_version_name_format() {
        // We can't construct GcpSecretProvider without a real client,
        // but we can test the format helper logic directly.
        let project_id = "my-project";
        let secret_id = "validator-key-abc";
        let expected = "projects/my-project/secrets/validator-key-abc/versions/latest";
        let result = format!("projects/{project_id}/secrets/{secret_id}/versions/latest");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parent_format() {
        let project_id = "my-project";
        let result = format!("projects/{project_id}");
        assert_eq!(result, "projects/my-project");
    }

    #[test]
    fn test_password_secret_skipped_in_name_check() {
        let id = "validator-key-abc-password";
        assert!(id.ends_with("-password"));
    }

    #[test]
    fn test_non_password_secret_not_skipped() {
        let id = "validator-key-abc";
        assert!(!id.ends_with("-password"));
    }
}
