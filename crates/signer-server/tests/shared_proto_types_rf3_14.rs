//! RF3-14: client and server share one generated type set.
//!
//! Before the shared crate, `bin/rvc-signer` and `crates/grpc-signer` each ran
//! `tonic_build`, producing structurally identical but distinct Rust types.
//! This test only compiles if both crates re-export the same `SignBeaconBlockRequest`.

#[test]
fn test_client_and_server_share_one_sign_request_type() {
    // Workspace alias package name is `grpc_signer` (see bin/rvc-signer Cargo.toml).
    use grpc_signer::proto::signer_v2::SignBeaconBlockRequest as ClientReq;
    use signer_server::proto::signer_v2::SignBeaconBlockRequest as ServerReq;

    // Construct via the client crate's path…
    let from_client =
        ClientReq { pubkey: vec![0u8; 48], fork_info: None, block_ssz: vec![0u8; 84], fork_id: 4 };

    // …and move into a parameter typed by the server crate's path.
    // Distinct generated types make this a compile error (the pre-RF3-14 state).
    fn accept_server(req: ServerReq) -> usize {
        req.pubkey.len()
    }

    assert_eq!(accept_server(from_client), 48);

    // TypeId identity is belt-and-suspenders for the same guarantee at runtime.
    assert_eq!(std::any::TypeId::of::<ClientReq>(), std::any::TypeId::of::<ServerReq>());
}
