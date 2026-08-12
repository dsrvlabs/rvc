//! Integration tests for the DVT allow-list loader.
//!
//! All tests are gated on the `dvt` feature because `AllowedPeers` lives in
//! the dvt module.

#![cfg(feature = "dvt")]

use std::io::Write;
use std::path::Path;

use rvc_signer_bin::dvt::allow_list::{AllowListError, AllowedPeer, AllowedPeers};

fn write_toml(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

// --------------------------------------------------------------------------
// Test 1: happy parse
// --------------------------------------------------------------------------

#[test]
fn test_load_dvt_allowed_peers_toml() {
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

    assert_eq!(
        allowed.peers[0],
        AllowedPeer { peer_cn: "peer-A".to_string(), share_index: 1, addr: None }
    );
    assert_eq!(
        allowed.peers[1],
        AllowedPeer { peer_cn: "peer-B".to_string(), share_index: 2, addr: None }
    );
}

// --------------------------------------------------------------------------
// Test 2: invalid format → parse error
// --------------------------------------------------------------------------

#[test]
fn test_load_dvt_allowed_peers_toml_invalid_format() {
    let f = write_toml("[not valid toml = ");
    let err = AllowedPeers::load_from_path(f.path()).unwrap_err();
    assert!(matches!(err, AllowListError::Parse(_)), "expected AllowListError::Parse, got: {err}");
}

// --------------------------------------------------------------------------
// Test 3: empty peer list → error
// --------------------------------------------------------------------------

#[test]
fn test_load_dvt_allowed_peers_toml_empty_peer_list() {
    // An empty file results in AllowListError::Empty.
    let f = write_toml("");
    let err = AllowedPeers::load_from_path(f.path()).unwrap_err();
    assert!(
        matches!(err, AllowListError::Empty),
        "expected AllowListError::Empty for empty file, got: {err}"
    );
}

// --------------------------------------------------------------------------
// Test 4: startup refuses when DVT enabled and allow-list file is missing
// --------------------------------------------------------------------------

#[test]
fn test_refuse_start_dvt_enabled_no_allow_list_file() {
    // Simulate the startup gate: trying to load a non-existent file must fail.
    let missing = Path::new("/nonexistent/dvt-allowed-peers.toml");
    let result = AllowedPeers::load_from_path(missing);
    assert!(result.is_err(), "must fail for missing file");

    let err = result.unwrap_err();
    assert!(
        matches!(err, AllowListError::Io { .. }),
        "expected Io error for missing file, got: {err}"
    );

    // The error message should contain the path and be actionable.
    let msg = err.to_string();
    assert!(
        msg.contains("nonexistent") || msg.contains("dvt-allowed-peers"),
        "error message should contain the path: {msg}"
    );
}

// --------------------------------------------------------------------------
// Test 5: lookup_by_cn — found
// --------------------------------------------------------------------------

#[test]
fn test_lookup_by_cn_found() {
    let f = write_toml(
        r#"
[[peer]]
peer_cn = "node-1"
share_index = 10
"#,
    );
    let allowed = AllowedPeers::load_from_path(f.path()).unwrap();
    let peer = allowed.lookup_by_cn("node-1").unwrap();
    assert_eq!(peer.share_index, 10);
}

// --------------------------------------------------------------------------
// Test 6: lookup_by_cn — not found
// --------------------------------------------------------------------------

#[test]
fn test_lookup_by_cn_not_found() {
    let f = write_toml(
        r#"
[[peer]]
peer_cn = "node-1"
share_index = 10
"#,
    );
    let allowed = AllowedPeers::load_from_path(f.path()).unwrap();
    assert!(allowed.lookup_by_cn("node-2").is_none());
}
