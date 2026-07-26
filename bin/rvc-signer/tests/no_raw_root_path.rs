//! Final assertion test: the v2 signer contract must not accept a raw
//! `signing_root` from the caller.
//!
//! All 10 typed RPCs compute the signing root server-side.  If any RPC were
//! added that accepted a raw 32-byte `signing_root` from the caller, that
//! would re-introduce C-2 / C-3 (caller can influence the root).  This test
//! greps the shared proto source (RF3-14: compiled once in `rvc-signer-proto`)
//! and asserts no such field exists.
//!
//! Per ISSUE-1.6d §"Final assertion test".

#[test]
fn test_no_v2_rpc_accepts_raw_signing_root() {
    // Workspace root: bin/rvc-signer → ../..
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let proto_path = root.join("proto/signer.v2.proto");

    let content = std::fs::read_to_string(&proto_path)
        .unwrap_or_else(|e| panic!("signer.v2.proto missing at {}: {}", proto_path.display(), e));

    assert!(
        !content.contains("signing_root"),
        "signer.v2.proto must not contain any `signing_root` field — \
         v2 typed RPCs must compute the signing root server-side. \
         Found in: {}",
        proto_path.display()
    );
}
