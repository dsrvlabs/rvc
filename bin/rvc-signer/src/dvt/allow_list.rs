//! DVT peer allow-list loader.
//!
//! Loads `dvt-allowed-peers.toml` at startup. Each entry binds a peer's mTLS
//! Common Name to its Shamir share index. The server enforces that the
//! `requester_index` field in every `Partial*` request matches the share index
//! recorded for the authenticated CN.
//!
//! # File format
//!
//! ```toml
//! [[peer]]
//! peer_cn = "peer-A"
//! share_index = 1
//!
//! [[peer]]
//! peer_cn = "peer-B"
//! share_index = 2
//! ```
//!
//! # Startup gate
//!
//! When DVT is enabled, the absence of this file is a fatal configuration
//! error.  Call [`AllowedPeers::load_from_path`] at startup and propagate the
//! error before binding the gRPC server.

use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

/// Error returned by the allow-list loader.
#[derive(Debug, Error)]
pub enum AllowListError {
    /// The file could not be read (missing, permissions, etc.).
    #[error("failed to read dvt-allowed-peers.toml at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The TOML content could not be parsed.
    #[error("failed to parse dvt-allowed-peers.toml: {0}")]
    Parse(#[from] toml::de::Error),

    /// The file was parsed successfully but the `[[peer]]` list is empty.
    #[error("dvt-allowed-peers.toml must contain at least one [[peer]] entry")]
    Empty,
}

/// A single entry in the allow-list file.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AllowedPeer {
    /// The mTLS Common Name of the peer.
    pub peer_cn: String,
    /// The Shamir share index assigned to this peer.
    pub share_index: u64,
}

/// Raw deserialization target — `peer` key is optional so that missing/empty
/// files can be turned into [`AllowListError::Empty`] rather than a parse error.
#[derive(Debug, Deserialize)]
struct AllowedPeersRaw {
    #[serde(rename = "peer", default)]
    peers: Vec<AllowedPeer>,
}

/// The parsed `dvt-allowed-peers.toml`.
#[derive(Debug, Clone)]
pub struct AllowedPeers {
    /// All configured peers.
    pub peers: Vec<AllowedPeer>,
}

impl AllowedPeers {
    /// Load and parse the allow-list from `path`.
    ///
    /// # Errors
    ///
    /// - [`AllowListError::Io`] — file cannot be read.
    /// - [`AllowListError::Parse`] — TOML syntax error or wrong schema.
    /// - [`AllowListError::Empty`] — the `[[peer]]` list has zero entries.
    pub fn load_from_path(path: &Path) -> Result<Self, AllowListError> {
        let content = std::fs::read_to_string(path)
            .map_err(|source| AllowListError::Io { path: path.display().to_string(), source })?;

        let raw: AllowedPeersRaw = toml::from_str(&content)?;

        if raw.peers.is_empty() {
            return Err(AllowListError::Empty);
        }

        Ok(Self { peers: raw.peers })
    }

    /// Look up a peer by its mTLS Common Name.
    ///
    /// Returns `None` if no entry with the given CN exists.
    pub fn lookup_by_cn(&self, peer_cn: &str) -> Option<&AllowedPeer> {
        self.peers.iter().find(|p| p.peer_cn == peer_cn)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write_toml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // ── load_from_path tests ──────────────────────────────────────────────────

    #[test]
    fn test_load_dvt_allowed_peers_toml_happy_path() {
        let f = write_toml(
            r#"
[[peer]]
peer_cn = "peer-A"
share_index = 1

[[peer]]
peer_cn = "peer-B"
share_index = 2
"#,
        );

        let allowed = AllowedPeers::load_from_path(f.path()).unwrap();
        assert_eq!(allowed.peers.len(), 2);
        assert_eq!(allowed.peers[0].peer_cn, "peer-A");
        assert_eq!(allowed.peers[0].share_index, 1);
        assert_eq!(allowed.peers[1].peer_cn, "peer-B");
        assert_eq!(allowed.peers[1].share_index, 2);
    }

    #[test]
    fn test_load_dvt_allowed_peers_toml_invalid_format() {
        let f = write_toml("[not valid toml for this schema = ");
        let err = AllowedPeers::load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, AllowListError::Parse(_)), "expected Parse error, got: {err}");
    }

    #[test]
    fn test_load_dvt_allowed_peers_toml_wrong_schema_produces_empty() {
        // Valid TOML but wrong schema — no [[peer]] table → empty list
        let f = write_toml(
            r#"
[config]
name = "test"
"#,
        );
        // The missing `peer` key deserialises as an empty Vec (serde default).
        // That triggers AllowListError::Empty.
        let err = AllowedPeers::load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, AllowListError::Empty), "expected Empty error, got: {err}");
    }

    #[test]
    fn test_load_dvt_allowed_peers_toml_empty_peer_list_is_error() {
        // An explicit empty peer list is also an error.
        let f = write_toml("");
        let err = AllowedPeers::load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, AllowListError::Empty), "expected Empty error, got: {err}");
    }

    #[test]
    fn test_load_dvt_allowed_peers_toml_file_missing_returns_io_error() {
        let err = AllowedPeers::load_from_path(Path::new("/nonexistent/dvt-allowed-peers.toml"))
            .unwrap_err();
        assert!(matches!(err, AllowListError::Io { .. }), "expected Io error, got: {err}");
    }

    // ── lookup_by_cn tests ────────────────────────────────────────────────────

    #[test]
    fn test_lookup_by_cn_found() {
        let allowed = AllowedPeers {
            peers: vec![
                AllowedPeer { peer_cn: "peer-A".to_string(), share_index: 1 },
                AllowedPeer { peer_cn: "peer-B".to_string(), share_index: 2 },
            ],
        };
        let peer = allowed.lookup_by_cn("peer-A").unwrap();
        assert_eq!(peer.share_index, 1);
    }

    #[test]
    fn test_lookup_by_cn_not_found_returns_none() {
        let allowed = AllowedPeers {
            peers: vec![AllowedPeer { peer_cn: "peer-A".to_string(), share_index: 1 }],
        };
        assert!(allowed.lookup_by_cn("peer-X").is_none());
    }

    #[test]
    fn test_lookup_by_cn_case_sensitive() {
        let allowed = AllowedPeers {
            peers: vec![AllowedPeer { peer_cn: "Peer-A".to_string(), share_index: 1 }],
        };
        assert!(allowed.lookup_by_cn("peer-a").is_none());
        assert!(allowed.lookup_by_cn("Peer-A").is_some());
    }
}
