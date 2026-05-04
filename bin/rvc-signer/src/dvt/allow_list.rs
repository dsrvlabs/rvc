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
//! peer_cn = "peer-a.cluster.local"
//! share_index = 1
//! addr = "peer-a.cluster.local:50051"   # optional; enables client-side SNI pinning
//!
//! [[peer]]
//! peer_cn = "peer-b.cluster.local"
//! share_index = 2
//! addr = "peer-b.cluster.local:50052"
//! ```
//!
//! The `addr` field is optional.  When present, the DVT client sets
//! `domain_name(peer_cn)` on the per-peer `ClientTlsConfig` before dialling,
//! preventing a certificate valid for one peer from being accepted for another
//! (ISSUE-4.1 / L-1 fix).  When absent, SNI pinning is skipped for that peer
//! and a warning is emitted at connect time.
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
    ///
    /// Must be a valid DNS name (e.g. `"peer-a.cluster.local"`).
    /// Used as both the allow-list identity and the TLS SNI hostname when
    /// `addr` is set (ISSUE-4.1 / L-1 SNI pinning fix).
    pub peer_cn: String,
    /// The Shamir share index assigned to this peer.
    pub share_index: u64,
    /// Optional TCP address of this peer (e.g. `"peer-a.cluster.local:50051"`).
    ///
    /// When set, `GrpcPeerRequester::connect` looks up this address in the
    /// allow-list and pins the TLS SNI to `peer_cn` before dialling.
    /// Without this field, SNI is not pinned for the peer and a warning is
    /// logged.
    #[serde(default)]
    pub addr: Option<String>,
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

    /// Look up a peer by its TCP address.
    ///
    /// Returns `None` if no entry has `addr` matching the given string.
    /// Entries whose `addr` field is `None` are never matched.
    ///
    /// Used by `GrpcPeerRequester::connect` to derive the SNI hostname for
    /// each outbound DVT peer connection (ISSUE-4.1 / L-1 fix).
    pub fn lookup_by_addr(&self, addr: &str) -> Option<&AllowedPeer> {
        self.peers.iter().find(|p| p.addr.as_deref() == Some(addr))
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
                AllowedPeer { peer_cn: "peer-A".to_string(), share_index: 1, addr: None },
                AllowedPeer { peer_cn: "peer-B".to_string(), share_index: 2, addr: None },
            ],
        };
        let peer = allowed.lookup_by_cn("peer-A").unwrap();
        assert_eq!(peer.share_index, 1);
    }

    #[test]
    fn test_lookup_by_cn_not_found_returns_none() {
        let allowed = AllowedPeers {
            peers: vec![AllowedPeer { peer_cn: "peer-A".to_string(), share_index: 1, addr: None }],
        };
        assert!(allowed.lookup_by_cn("peer-X").is_none());
    }

    #[test]
    fn test_lookup_by_cn_case_sensitive() {
        let allowed = AllowedPeers {
            peers: vec![AllowedPeer { peer_cn: "Peer-A".to_string(), share_index: 1, addr: None }],
        };
        assert!(allowed.lookup_by_cn("peer-a").is_none());
        assert!(allowed.lookup_by_cn("Peer-A").is_some());
    }

    // ── lookup_by_addr tests ────────────────────────────���─────────────────────

    #[test]
    fn test_lookup_by_addr_found() {
        let allowed = AllowedPeers {
            peers: vec![
                AllowedPeer {
                    peer_cn: "peer-a.local".to_string(),
                    share_index: 1,
                    addr: Some("peer-a.local:50051".to_string()),
                },
                AllowedPeer {
                    peer_cn: "peer-b.local".to_string(),
                    share_index: 2,
                    addr: Some("peer-b.local:50052".to_string()),
                },
            ],
        };
        let hit = allowed.lookup_by_addr("peer-a.local:50051").unwrap();
        assert_eq!(hit.peer_cn, "peer-a.local");
        assert_eq!(hit.share_index, 1);
    }

    #[test]
    fn test_lookup_by_addr_not_found() {
        let allowed = AllowedPeers {
            peers: vec![AllowedPeer {
                peer_cn: "peer-a.local".to_string(),
                share_index: 1,
                addr: Some("peer-a.local:50051".to_string()),
            }],
        };
        assert!(allowed.lookup_by_addr("peer-x.local:50051").is_none());
    }

    #[test]
    fn test_lookup_by_addr_none_field_not_matched() {
        let allowed = AllowedPeers {
            peers: vec![AllowedPeer {
                peer_cn: "peer-a.local".to_string(),
                share_index: 1,
                addr: None,
            }],
        };
        // Entries without addr can never be matched by address.
        assert!(allowed.lookup_by_addr("peer-a.local:50051").is_none());
    }

    // ── addr field TOML round-trip ────────────────────────────��───────────────

    #[test]
    fn test_load_with_addr_field() {
        let f = write_toml(
            r#"
[[peer]]
peer_cn = "peer-a.cluster.local"
share_index = 1
addr = "peer-a.cluster.local:50051"

[[peer]]
peer_cn = "peer-b.cluster.local"
share_index = 2
"#,
        );

        let allowed = AllowedPeers::load_from_path(f.path()).unwrap();
        assert_eq!(allowed.peers[0].addr, Some("peer-a.cluster.local:50051".to_string()));
        // addr is optional; second peer has no addr
        assert_eq!(allowed.peers[1].addr, None);
    }
}
