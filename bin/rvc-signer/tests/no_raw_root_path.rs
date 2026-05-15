//! Final assertion test: the generated `signer.v2.rs` must not contain any
//! field named `signing_root`.
//!
//! All 10 typed RPCs compute the signing root server-side.  If any RPC were
//! added that accepted a raw 32-byte `signing_root` from the caller, that
//! would re-introduce C-2 / C-3 (caller can influence the root).  This test
//! greps the generated Rust code and asserts no such field exists.
//!
//! Per ISSUE-1.6d §"Final assertion test".

#[test]
fn test_no_v2_rpc_accepts_raw_signing_root() {
    // `env!("OUT_DIR")` is set by Cargo to the build output directory for the
    // current crate.  tonic-build writes the generated Rust module there.
    let out_dir = env!("OUT_DIR");
    let proto_path = std::path::Path::new(out_dir).join("signer.v2.rs");

    let content = std::fs::read_to_string(&proto_path)
        .unwrap_or_else(|e| panic!("signer.v2.rs missing at {}: {}", proto_path.display(), e));

    assert!(
        !content.contains("signing_root"),
        "signer.v2.rs must not contain any `signing_root` field — \
         v2 typed RPCs must compute the signing root server-side. \
         Found in: {}",
        proto_path.display()
    );
}
